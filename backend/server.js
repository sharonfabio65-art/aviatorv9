const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { createClient } = require('@supabase/supabase-js');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// ============ CORS ============
const corsOptions = {
  origin: [
    'https://aviatorpredictor-v9.netlify.app',
    'http://localhost:3000',
    'http://localhost:5500',
    'http://127.0.0.1:5500'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// ============ MIDDLEWARE ============
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

app.use(express.json({ limit: '200mb' }));
app.use(express.urlencoded({ extended: true, limit: '200mb' }));

// Increase timeout for uploads
app.use((req, res, next) => {
  req.setTimeout(120000); // 2 minutes
  res.setTimeout(120000);
  next();
});

app.use((req, res, next) => {
  console.log(`📥 ${req.method} ${req.url}`);
  next();
});

// ============ RATE LIMITING ============
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  skip: () => true
});
app.use('/api/', limiter);

// ============ SUPABASE ============
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);
console.log('✅ Supabase initialized');

// ============ DATABASE ============
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ============ DATABASE INITIALIZATION ============
async function initDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS versions (
        id SERIAL PRIMARY KEY,
        version_name VARCHAR(50) NOT NULL,
        version_number VARCHAR(20) NOT NULL,
        file_name VARCHAR(255) NOT NULL,
        file_path VARCHAR(500) NOT NULL,
        file_size INTEGER,
        file_url TEXT,
        upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN DEFAULT TRUE
      )
    `);
    console.log('✅ Versions table ready');

    await pool.query(`
      CREATE TABLE IF NOT EXISTS site_config (
        id SERIAL PRIMARY KEY,
        config_key VARCHAR(100) UNIQUE NOT NULL,
        config_value TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('✅ Site config table ready');

    const defaultConfig = [
      ['youtube_url', 'https://youtube.com/@aviator'],
      ['whatsapp_group_url', 'https://chat.whatsapp.com/yourgroup'],
      ['telegram_url', 'https://t.me/aviatorchannel'],
      ['admin_whatsapp', '1234567890'],
      ['admin_telegram', 'aviator_admin']
    ];

    for (const [key, value] of defaultConfig) {
      await pool.query(
        `INSERT INTO site_config (config_key, config_value) 
         VALUES ($1, $2) 
         ON CONFLICT (config_key) 
         DO UPDATE SET config_value = $2, updated_at = CURRENT_TIMESTAMP`,
        [key, value]
      );
    }
    console.log('✅ Database initialization complete');
  } catch (error) {
    console.error('❌ Database initialization error:', error);
  }
}

// ============ MULTER ============
const uploadDir = path.join(__dirname, 'temp_uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const timestamp = Date.now();
    const ext = path.extname(file.originalname);
    const name = path.basename(file.originalname, ext);
    cb(null, `${name}_${timestamp}${ext}`);
  }
});

const fileFilter = (req, file, cb) => {
  if (file.mimetype === 'application/vnd.android.package-archive' || 
      file.originalname.endsWith('.apk')) {
    cb(null, true);
  } else {
    cb(new Error('Only APK files are allowed'), false);
  }
};

const upload = multer({ 
  storage: storage,
  fileFilter: fileFilter,
  limits: { fileSize: 200 * 1024 * 1024 } // Increased to 200MB
});

// ============ AUTHENTICATION ============
function authenticateAdmin(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ success: false, message: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.admin = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ success: false, message: 'Invalid token' });
  }
}

// ============ HEALTH CHECK ============
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    database: 'Neon PostgreSQL',
    storage: 'Supabase'
  });
});

// ============ API ROUTES ============

// Admin Login
app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email and password required' 
      });
    }

    if (email === process.env.ADMIN_EMAIL && 
        password === process.env.ADMIN_PASSWORD) {
      
      const token = jwt.sign(
        { email: email, role: 'admin' },
        process.env.JWT_SECRET,
        { expiresIn: '24h' }
      );

      return res.json({
        success: true,
        token: token,
        message: 'Login successful'
      });
    } else {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Verify Token
app.get('/api/admin/verify', authenticateAdmin, (req, res) => {
  res.json({ success: true, message: 'Token valid' });
});

// Upload APK
app.post('/api/admin/upload', authenticateAdmin, (req, res, next) => {
  // Set timeout for this specific route
  req.setTimeout(180000); // 3 minutes
  res.setTimeout(180000);
  next();
}, upload.single('apkFile'), async (req, res) => {
  try {
    console.log('📤 Upload request received');
    const { versionName, versionNumber } = req.body;
    const file = req.file;

    if (!file) {
      return res.status(400).json({
        success: false,
        message: 'No file uploaded'
      });
    }

    if (!versionName || !versionNumber) {
      return res.status(400).json({
        success: false,
        message: 'Version name and number are required'
      });
    }

    console.log('📄 File:', file.originalname, file.size, 'bytes');

    // Read file
    const fileBuffer = fs.readFileSync(file.path);
    const fileName = `apks/${Date.now()}_${file.originalname}`;
    
    console.log('📤 Uploading to Supabase...');
    
    // Upload to Supabase with progress
    const { data: uploadData, error: uploadError } = await supabase.storage
      .from('apks')
      .upload(fileName, fileBuffer, {
        contentType: 'application/vnd.android.package-archive',
        cacheControl: '3600'
      });

    // Clean up temp file
    try {
      fs.unlinkSync(file.path);
      console.log('🗑️ Temp file deleted');
    } catch (err) {
      console.log('⚠️ Could not delete temp file:', err.message);
    }

    if (uploadError) {
      console.error('❌ Supabase upload error:', uploadError);
      return res.status(500).json({
        success: false,
        message: 'Failed to upload to storage: ' + uploadError.message
      });
    }

    console.log('✅ Uploaded to Supabase');

    // Get public URL
    const { data: urlData } = supabase.storage
      .from('apks')
      .getPublicUrl(fileName);

    const fileUrl = urlData.publicUrl;
    console.log('✅ File URL:', fileUrl);

    // Deactivate all previous versions
    await pool.query('UPDATE versions SET is_active = false WHERE is_active = true');

    // Insert new version
    const result = await pool.query(
      `INSERT INTO versions (version_name, version_number, file_name, file_path, file_size, file_url, is_active)
       VALUES ($1, $2, $3, $4, $5, $6, true)
       RETURNING *`,
      [versionName, versionNumber, file.originalname, fileName, file.size, fileUrl]
    );

    console.log('✅ APK uploaded successfully');
    res.json({
      success: true,
      message: 'APK uploaded successfully',
      version: result.rows[0],
      downloadUrl: fileUrl
    });
  } catch (error) {
    console.error('❌ Upload error:', error);
    res.status(500).json({
      success: false,
      message: 'Upload failed',
      error: error.message
    });
  }
});

// Get active version
app.get('/api/active-version', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT version_name, version_number, file_name, file_url, upload_date FROM versions WHERE is_active = true ORDER BY upload_date DESC LIMIT 1'
    );

    if (result.rows.length === 0) {
      return res.json({
        success: false,
        message: 'No version found'
      });
    }

    res.json({
      success: true,
      version: result.rows[0]
    });
  } catch (error) {
    console.error('Error fetching version:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Get all versions
app.get('/api/admin/versions', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM versions ORDER BY upload_date DESC'
    );
    res.json({
      success: true,
      versions: result.rows
    });
  } catch (error) {
    console.error('Error fetching versions:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Download latest APK
app.get('/api/download', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT file_url, file_name FROM versions WHERE is_active = true ORDER BY upload_date DESC LIMIT 1'
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'No APK available for download'
      });
    }

    const { file_url, file_name } = result.rows[0];
    
    if (!file_url) {
      return res.status(404).json({
        success: false,
        message: 'No file URL found'
      });
    }

    return res.redirect(file_url);
  } catch (error) {
    console.error('Download error:', error);
    res.status(500).json({
      success: false,
      message: 'Download failed'
    });
  }
});

// Get public config
app.get('/api/public-config', async (req, res) => {
  try {
    const result = await pool.query('SELECT config_key, config_value FROM site_config');
    
    const config = {};
    result.rows.forEach(row => {
      config[row.config_key] = row.config_value;
    });

    const quotes = [
      { text: "Risk comes from not knowing what you're doing.", author: "Warren Buffett" },
      { text: "The biggest risk is not taking any risk.", author: "Mark Zuckerberg" },
      { text: "Fortune favors the bold.", author: "Latin Proverb" },
      { text: "Confidence is the companion of success.", author: "Unknown" },
      { text: "Winning isn't everything, but wanting to win is.", author: "Vince Lombardi" },
      { text: "Money grows on the tree of persistence.", author: "Japanese Proverb" },
      { text: "A winning mindset sees opportunity in every difficulty.", author: "Aviator" },
      { text: "Success is where preparation and opportunity meet.", author: "Bobby Unser" },
      { text: "Don't watch the clock; do what it does. Keep going.", author: "Sam Levenson" },
      { text: "The harder you work, the luckier you get.", author: "Gary Player" }
    ];

    res.json({
      success: true,
      config: config,
      quotes: quotes
    });
  } catch (error) {
    console.error('Config error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch config'
    });
  }
});

// Update config
app.post('/api/admin/config', authenticateAdmin, async (req, res) => {
  try {
    const updates = req.body;
    
    for (const [key, value] of Object.entries(updates)) {
      await pool.query(
        `INSERT INTO site_config (config_key, config_value) 
         VALUES ($1, $2) 
         ON CONFLICT (config_key) 
         DO UPDATE SET config_value = $2, updated_at = CURRENT_TIMESTAMP`,
        [key, value]
      );
    }

    res.json({
      success: true,
      message: 'Config updated successfully'
    });
  } catch (error) {
    console.error('Update config error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update config'
    });
  }
});

// Delete version
app.delete('/api/admin/version/:id', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    const result = await pool.query('SELECT file_path FROM versions WHERE id = $1', [id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Version not found'
      });
    }

    const filePath = result.rows[0].file_path;
    if (filePath) {
      await supabase.storage.from('apks').remove([filePath]);
    }

    await pool.query('DELETE FROM versions WHERE id = $1', [id]);

    res.json({
      success: true,
      message: 'Version deleted successfully'
    });
  } catch (error) {
    console.error('Delete error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete version'
    });
  }
});

// ============ ERROR HANDLING ============
app.use((err, req, res, next) => {
  console.error('❌ Error:', err.stack);
  res.status(500).json({
    success: false,
    message: err.message || 'Something went wrong!'
  });
});

// ============ START SERVER ============
initDatabase().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`✅ CORS enabled for: https://aviatorpredictor-v9.netlify.app`);
  });
}).catch(err => {
  console.error('❌ Failed to initialize database:', err);
  process.exit(1);
});

module.exports = app;
