const { createClient } = require('redis');
const logger = require('../utils/logger');

let redisClient;

const initializeRedis = async () => {
  try {
    redisClient = createClient({
      url: `redis://${process.env.REDIS_HOST}:${process.env.REDIS_PORT}`,
      password: process.env.REDIS_PASSWORD || undefined,
      socket: {
        reconnectStrategy: (retries) => {
          if (retries > 10) {
            logger.error('❌ Too many retries for Redis connection');
            return new Error('Too many retries');
          }
          return Math.min(retries * 100, 3000);
        }
      }
    });

    redisClient.on('error', (err) => {
      logger.error('Redis error:', err);
    });

    redisClient.on('connect', () => {
      logger.info('✅ Redis connected successfully');
    });

    redisClient.on('reconnecting', () => {
      logger.info('🔄 Redis reconnecting...');
    });

    await redisClient.connect();
    return redisClient;
  } catch (error) {
    logger.error('❌ Failed to connect to Redis:', error);
    // Create a mock client for development if Redis is unavailable
    return createMockRedisClient();
  }
};

// Mock Redis client for development when Redis is unavailable
const createMockRedisClient = () => {
  const mockData = new Map();
  
  return {
    async get(key) {
      return mockData.get(key);
    },
    async set(key, value, options = {}) {
      mockData.set(key, value);
      if (options.EX) {
        setTimeout(() => {
          mockData.delete(key);
        }, options.EX * 1000);
      }
      return 'OK';
    },
    async del(key) {
      return mockData.delete(key) ? 1 : 0;
    },
    async incr(key) {
      const current = parseInt(mockData.get(key) || 0);
      const newValue = current + 1;
      mockData.set(key, newValue.toString());
      return newValue;
    },
    async expire(key, seconds) {
      setTimeout(() => {
        mockData.delete(key);
      }, seconds * 1000);
      return 1;
    },
    async ttl(key) {
      // Mock TTL - always return 60 seconds
      return 60;
    },
    async keys(pattern) {
      const allKeys = Array.from(mockData.keys());
      const regex = new RegExp(pattern.replace('*', '.*'));
      return allKeys.filter(key => regex.test(key));
    },
    async quit() {
      mockData.clear();
      return 'OK';
    },
    isMock: true
  };
};

const getRedisClient = () => {
  if (!redisClient) {
    throw new Error('Redis client not initialized. Call initializeRedis() first.');
  }
  return redisClient;
};

module.exports = {
  initializeRedis,
  getRedisClient
};
