const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const userAgent = require('express-useragent');
const logger = require('./utils/logger');

// Import middleware
const securityMiddleware = require('./middleware/security');
const ipLimitMiddleware = require('./middleware/ipLimit');
const rateLimitMiddleware = require('./middleware/rateLimit');
const errorHandler = require('./middleware/errorHandler');

// Import routes
const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');
const taskRoutes = require('./routes/taskRoutes');
const moonPointRoutes = require('./routes/moonPointRoutes');
const securityRoutes = require('./routes/securityRoutes');
const adminRoutes = require('./routes/adminRoutes');

const app = express();

// Trust proxy for IP detection
app.set('trust proxy', true);

// Security headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            scriptSrc: ["'self'", "https://cdnjs.cloudflare.com", "https://hcaptcha.com", "https://*.hcaptcha.com"],
            frameSrc: ["'self'", "https://hcaptcha.com", "https://*.hcaptcha.com"],
            connectSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"]
        }
    }
}));

// Enable CORS
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:8080',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Device-Fingerprint', 'X-Client-Version']
}));

// Body parser with limits
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// User agent parsing
app.use(userAgent.express());

// Data sanitization against NoSQL query injection
app.use(mongoSanitize());

// Data sanitization against XSS
app.use(xss());

// Request logging middleware
app.use((req, res, next) => {
    const start = Date.now();
    const originalSend = res.send;
    
    res.send = function(body) {
        const duration = Date.now() - start;
        const message = `${req.method} ${req.originalUrl} ${res.statusCode} - ${duration}ms`;
        
        if (res.statusCode >= 400) {
            logger.warn(message);
        } else {
            logger.info(message);
        }
        
        return originalSend.call(this, body);
    };
    
    next();
});

// IP validation middleware
app.use(ipLimitMiddleware.validateIP);

// Bot detection middleware
app.use(securityMiddleware.detectBot);

// Request validation middleware
app.use(securityMiddleware.validateRequest);

// Rate limiting (applied to all routes)
app.use(rateLimitMiddleware.genericLimiter);

// IP limiting for sensitive routes
app.use('/api/auth/signup', ipLimitMiddleware.checkIPLimit);
app.use('/api/auth/social', ipLimitMiddleware.checkIPLimit);

// Slowing down for suspicious activity
app.use(rateLimitMiddleware.slowDownMiddleware);

// Routes with their own rate limits
app.use('/api/auth', rateLimitMiddleware.authLimiter, authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/tasks', rateLimitMiddleware.taskLimiter, taskRoutes);
app.use('/api/moonpoints', moonPointRoutes);
app.use('/api/security', securityRoutes);

// Admin routes with IP whitelist
app.use('/api/admin', ipLimitMiddleware.checkAdminIP, adminRoutes);

// Health check endpoint
app.get('/health', (req, res) => {
    res.status(200).json({ 
        status: 'healthy',
        service: 'wenmoon-backend',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        nodeVersion: process.version
    });
});

// System info endpoint (protected)
app.get('/api/system/info', securityMiddleware.requireAPIKey, (req, res) => {
    res.status(200).json({
        status: 'online',
        version: '1.0.0',
        environment: process.env.NODE_ENV,
        security: {
            ipLimiting: process.env.IP_LIMITING_ENABLED === 'true',
            maxUsersPerIP: parseInt(process.env.MAX_USERS_PER_IP || '5'),
            captchaEnabled: process.env.CAPTCHA_ENABLED === 'true'
        }
    });
});

// 404 handler
app.use('*', (req, res) => {
    logger.warn(`404 Route not found: ${req.method} ${req.originalUrl}`);
    res.status(404).json({
        status: 'error',
        message: 'Route not found',
        code: 'ROUTE_NOT_FOUND'
    });
});

// Global error handler
app.use(errorHandler);

module.exports = app;
