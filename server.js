require('dotenv').config();
const app = require('./src/app');
const mongoose = require('mongoose');
const logger = require('./src/utils/logger');
const { initDatabase } = require('./src/scripts/initDatabase');

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/wenmoon';

// Graceful shutdown handler
const gracefulShutdown = async () => {
    logger.info('Received shutdown signal, closing connections...');
    
    try {
        await mongoose.connection.close();
        logger.info('MongoDB connection closed');
        process.exit(0);
    } catch (error) {
        logger.error('Error during shutdown:', error);
        process.exit(1);
    }
};

// Connect to MongoDB
const connectDB = async () => {
    try {
        await mongoose.connect(MONGODB_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            serverSelectionTimeoutMS: 5000,
            socketTimeoutMS: 45000,
        });
        
        logger.info('Connected to MongoDB');
        
        // Initialize database with default data
        await initDatabase();
        
        // Start server
        const server = app.listen(PORT, () => {
            logger.info(`Server running on port ${PORT} in ${process.env.NODE_ENV} mode`);
        });
        
        // Handle graceful shutdown
        process.on('SIGTERM', gracefulShutdown);
        process.on('SIGINT', gracefulShutdown);
        
        // Handle unhandled rejections
        process.on('unhandledRejection', (err) => {
            logger.error('Unhandled Promise Rejection:', err);
            // Don't exit in production, just log
            if (process.env.NODE_ENV === 'development') {
                process.exit(1);
            }
        });
        
        // Handle uncaught exceptions
        process.on('uncaughtException', (err) => {
            logger.error('Uncaught Exception:', err);
            // Exit in production to restart
            process.exit(1);
        });
        
    } catch (error) {
        logger.error('MongoDB connection error:', error);
        
        // Retry connection after delay
        if (process.env.NODE_ENV !== 'production') {
            setTimeout(connectDB, 5000);
        } else {
            process.exit(1);
        }
    }
};

// Start the application
connectDB();
