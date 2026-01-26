module.exports = {
    // Application Security
    APP_SECURITY: {
        JWT_SECRET: process.env.JWT_SECRET || 'wenmoon-super-secret-key-change-in-production',
        JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN || '7d',
        ENCRYPTION_KEY: process.env.ENCRYPTION_KEY || 'encryption-key-32-chars-long-here',
        SALT_ROUNDS: 10
    },

    // Anti-bot configuration
    BOT_DETECTION: {
        ENABLED: process.env.BOT_DETECTION_ENABLED === 'true',
        BOT_USER_AGENTS: [
            'Googlebot', 'Bingbot', 'Slurp', 'DuckDuckBot', 'Baiduspider',
            'YandexBot', 'Sogou', 'Exabot', 'facebot', 'ia_archiver',
            'AhrefsBot', 'MJ12bot', 'SeznamBot', 'dotbot', 'SemrushBot',
            'CCBot', 'GPTBot', 'ChatGPT-User', 'anthropic-ai'
        ],
        SUSPICIOUS_PATTERNS: [
            'bot', 'crawler', 'spider', 'scraper', 'scan', 'checker',
            'headless', 'phantom', 'selenium', 'puppeteer', 'automation',
            'python-requests', 'curl', 'wget', 'postman', 'insomnia'
        ],
        // Headless browser detection
        HEADLESS_INDICATORS: {
            WEBDRIVER: 'webdriver',
            PERMISSIONS: 'permissions',
            LANGUAGES: 'languages',
            PLUGINS: 'plugins'
        }
    },

    // IP limiting configuration
    IP_LIMITING: {
        ENABLED: process.env.IP_LIMITING_ENABLED === 'true',
        MAX_USERS_PER_IP: parseInt(process.env.MAX_USERS_PER_IP || '5'),
        CHECK_VPN_PROXY: process.env.CHECK_VPN_PROXY === 'true',
        BAN_DURATION: 24 * 60 * 60 * 1000, // 24 hours
        TEMP_BAN_THRESHOLD: 5, // Temp ban after 5 violations
        PERM_BAN_THRESHOLD: 10, // Perm ban after 10 violations
        
        // IP ranges to block (private, local, etc.)
        BLOCKED_RANGES: [
            '192.168.0.0/16',
            '10.0.0.0/8',
            '172.16.0.0/12',
            '127.0.0.0/8',
            '169.254.0.0/16',
            '::1/128'
        ],
        
        // Cloud provider IP ranges (optional blocking)
        CLOUD_RANGES: [
            // Add AWS, Google Cloud, Azure ranges if needed
        ]
    },

    // CAPTCHA configuration
    CAPTCHA: {
        ENABLED: process.env.CAPTCHA_ENABLED === 'true',
        PROVIDER: process.env.CAPTCHA_PROVIDER || 'hcaptcha',
        HCAPTCHA_SECRET: process.env.HCAPTCHA_SECRET,
        HCAPTCHA_SITE_KEY: process.env.HCAPTCHA_SITE_KEY,
        RECAPTCHA_SECRET: process.env.RECAPTCHA_SECRET,
        RECAPTCHA_SITE_KEY: process.env.RECAPTCHA_SITE_KEY,
        MIN_SCORE: 0.5,
        REQUIRED_FOR: ['signup', 'password_reset', 'high_value_tasks']
    },

    // Fraud detection configuration
    FRAUD_DETECTION: {
        ENABLED: process.env.FRAUD_DETECTION_ENABLED === 'true',
        RISK_SCORING: {
            MULTIPLE_ACCOUNTS: 40,
            RAPID_ACTIVITY: 35,
            DISPOSABLE_EMAIL: 50,
            VPN_PROXY: 30,
            UNUSUAL_TIMING: 15,
            DEVICE_CHANGE: 20,
            GEO_MISMATCH: 25
        },
        THRESHOLDS: {
            HIGH_RISK: 80,
            MEDIUM_RISK: 50,
            LOW_RISK: 20
        },
        AUTO_ACTION: {
            FLAG_AT: 50,
            RESTRICT_AT: 70,
            BLOCK_AT: 90
        }
    },

    // Rate limiting configuration
    RATE_LIMITING: {
        WINDOW_MS: 15 * 60 * 1000, // 15 minutes
        MAX_REQUESTS: 100,
        AUTH_WINDOW_MS: 60 * 60 * 1000, // 1 hour
        AUTH_MAX_ATTEMPTS: 5,
        SIGNUP_WINDOW_MS: 24 * 60 * 60 * 1000, // 24 hours
        SIGNUP_MAX_ATTEMPTS: 3,
        TASK_WINDOW_MS: 5 * 60 * 1000, // 5 minutes
        TASK_MAX_ATTEMPTS: 10
    },

    // API Security
    API_SECURITY: {
        REQUIRE_API_KEY: process.env.REQUIRE_API_KEY === 'true',
        API_KEY_HEADER: 'X-API-Key',
        ALLOWED_ORIGINS: (process.env.ALLOWED_ORIGINS || 'http://localhost:8080').split(','),
        CORS_MAX_AGE: 86400 // 24 hours
    },

    // Monitoring
    MONITORING: {
        LOG_LEVEL: process.env.LOG_LEVEL || 'info',
        LOG_RETENTION_DAYS: 30,
        ALERT_THRESHOLDS: {
            HIGH_RISK_USERS: 5,
            BLOCKED_IPS: 10,
            SUSPICIOUS_REQUESTS: 50
        }
    }
};
