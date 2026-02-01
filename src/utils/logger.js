const winston = require('winston');
const path = require('path');
const fs = require('fs');

// Create logs directory if it doesn't exist
const logDir = process.env.LOG_DIRECTORY || 'logs';
if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true });
}

// Define log format
const logFormat = winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    winston.format.splat(),
    winston.format.json()
);

// Console format for development
const consoleFormat = winston.format.combine(
    winston.format.colorize(),
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.printf(({ timestamp, level, message, ...meta }) => {
        let log = `${timestamp} ${level}: ${message}`;
        
        if (Object.keys(meta).length > 0) {
            // Hide sensitive data
            const safeMeta = { ...meta };
            ['password', 'token', 'secret', 'authorization'].forEach(field => {
                if (safeMeta[field]) {
                    safeMeta[field] = '***REDACTED***';
                }
            });
            
            log += ` ${JSON.stringify(safeMeta)}`;
        }
        
        return log;
    })
);

// Create logger instance
const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: logFormat,
    defaultMeta: { service: 'wenmoon-backend' },
    transports: [
        // Console transport (always enabled)
        new winston.transports.Console({
            format: consoleFormat,
            level: process.env.NODE_ENV === 'development' ? 'debug' : 'info'
        })
    ]
});

// File transports (only in production or if explicitly enabled)
if (process.env.NODE_ENV === 'production' || process.env.LOG_TO_FILE === 'true') {
    // Error log file
    logger.add(new winston.transports.File({
        filename: path.join(logDir, process.env.ERROR_LOG_FILE || 'error.log'),
        level: 'error',
        maxsize: 5242880, // 5MB
        maxFiles: 5,
        tailable: true
    }));
    
    // Combined log file
    logger.add(new winston.transports.File({
        filename: path.join(logDir, process.env.COMBINED_LOG_FILE || 'combined.log'),
        maxsize: 5242880, // 5MB
        maxFiles: 10,
        tailable: true
    }));
    
    // Security log file
    logger.add(new winston.transports.File({
        filename: path.join(logDir, 'security.log'),
        level: 'warn',
        maxsize: 5242880, // 5MB
        maxFiles: 10,
        tailable: true,
        format: winston.format.combine(
            winston.format.timestamp(),
            winston.format.json()
        )
    }));
    
    // Audit log file (for important business events)
    logger.add(new winston.transports.File({
        filename: path.join(logDir, 'audit.log'),
        level: 'info',
        maxsize: 5242880, // 5MB
        maxFiles: 10,
        tailable: true,
        format: winston.format.combine(
            winston.format.timestamp(),
            winston.format.json()
        )
    }));
}

// Custom stream for Morgan HTTP logger
logger.stream = {
    write: (message) => {
        logger.info(message.trim());
    }
};

// Security logging helper
logger.security = {
    warn: (message, meta = {}) => {
        logger.warn(`[SECURITY] ${message}`, meta);
    },
    
    error: (message, meta = {}) => {
        logger.error(`[SECURITY] ${message}`, meta);
    },
    
    info: (message, meta = {}) => {
        logger.info(`[SECURITY] ${message}`, meta);
    }
};

// Audit logging helper
logger.audit = (event, userId, details = {}) => {
    logger.info(`[AUDIT] ${event}`, {
        userId,
        event,
        ...details,
        timestamp: new Date().toISOString()
    });
};

// Request logging middleware
logger.requestLogger = (req, res, next) => {
    const start = Date.now();
    
    // Log request
    logger.debug('Request received', {
        method: req.method,
        url: req.originalUrl,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        userId: req.userId || 'anonymous'
    });
    
    // Capture response
    const originalSend = res.send;
    res.send = function(body) {
        const duration = Date.now() - start;
        
        // Log response
        const logLevel = res.statusCode >= 400 ? 'warn' : 'info';
        logger.log(logLevel, 'Request completed', {
            method: req.method,
            url: req.originalUrl,
            statusCode: res.statusCode,
            duration: `${duration}ms`,
            ip: req.ip,
            userId: req.userId || 'anonymous',
            responseSize: res.get('Content-Length') || Buffer.byteLength(body || '', 'utf8')
        });
        
        return originalSend.call(this, body);
    };
    
    next();
};

// Error logging middleware
logger.errorLogger = (err, req, res, next) => {
    logger.error('Unhandled error', {
        error: err.message,
        stack: err.stack,
        method: req.method,
        url: req.originalUrl,
        ip: req.ip,
        userId: req.userId || 'anonymous'
    });
    
    next(err);
};

// Performance logging
logger.performance = (operation, duration, meta = {}) => {
    logger.debug(`[PERFORMANCE] ${operation} took ${duration}ms`, {
        operation,
        duration,
        ...meta
    });
};

// Database query logging (attach to Mongoose)
if (process.env.NODE_ENV === 'development') {
    const mongoose = require('mongoose');
    
    mongoose.set('debug', (collectionName, method, query, doc) => {
        logger.debug(`[MONGOOSE] ${collectionName}.${method}`, {
            query: JSON.stringify(query),
            doc
        });
    });
}

module.exports = logger;
