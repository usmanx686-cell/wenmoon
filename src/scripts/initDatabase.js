const mongoose = require('mongoose');
const User = require('../models/User');
const Task = require('../models/Task');
const BlockedIP = require('../models/BlockedIP');
const Whitelist = require('../models/Whitelist');
const logger = require('../utils/logger');

const defaultTasks = [
    {
        title: 'Follow on Twitter',
        description: 'Follow @WENMOON on Twitter and retweet our pinned post',
        category: 'social',
        points: 50,
        requiresProof: true,
        proofType: 'twitter_handle',
        dailyLimit: 1,
        status: 'active',
        icon: 'fab fa-twitter',
        metadata: {
            url: 'https://twitter.com/WENMOON',
            instructions: 'Follow our Twitter account and retweet the pinned post'
        }
    },
    {
        title: 'Join Telegram Group',
        description: 'Join our official Telegram group and stay for at least 24 hours',
        category: 'social',
        points: 40,
        requiresProof: true,
        proofType: 'telegram_username',
        dailyLimit: 1,
        status: 'active',
        icon: 'fab fa-telegram',
        metadata: {
            url: 'https://t.me/wenmoon',
            instructions: 'Join our Telegram group and keep the chat open'
        }
    },
    {
        title: 'Watch Video Ad',
        description: 'Watch a short sponsored video to earn Moon Points',
        category: 'engagement',
        points: 10,
        requiresProof: false,
        dailyLimit: 5,
        status: 'active',
        icon: 'fas fa-ad',
        metadata: {
            cooldown: 3600000, // 1 hour between watches
            maxDaily: 5
        }
    },
    {
        title: 'Refer a Friend',
        description: 'Invite friends using your referral link',
        category: 'referral',
        points: 100,
        requiresProof: true,
        proofType: 'referral_code',
        dailyLimit: 10,
        status: 'active',
        icon: 'fas fa-user-plus',
        metadata: {
            pointsPerReferral: 100,
            bonusForCompletion: 50
        }
    },
    {
        title: 'Join Discord Server',
        description: 'Join our Discord server and verify your account',
        category: 'social',
        points: 60,
        requiresProof: true,
        proofType: 'discord_username',
        dailyLimit: 1,
        status: 'active',
        icon: 'fab fa-discord',
        metadata: {
            url: 'https://discord.gg/wenmoon',
            instructions: 'Join Discord and verify in #verification channel'
        }
    },
    {
        title: 'Connect Wallet',
        description: 'Connect a Web3 wallet to earn bonus Moon Points',
        category: 'wallet',
        points: 80,
        requiresProof: false,
        requiresWallet: true,
        dailyLimit: 1,
        status: 'active',
        icon: 'fas fa-wallet',
        metadata: {
            supportedWallets: ['metamask', 'walletconnect', 'coinbase'],
            network: 'EVM'
        }
    },
    {
        title: 'Subscribe to Newsletter',
        description: 'Subscribe to our email newsletter for updates',
        category: 'engagement',
        points: 20,
        requiresProof: false,
        dailyLimit: 1,
        status: 'active',
        icon: 'fas fa-envelope',
        metadata: {
            autoVerify: true
        }
    },
    {
        title: 'Visit Daily',
        description: 'Visit the platform daily to earn points',
        category: 'engagement',
        points: 5,
        requiresProof: false,
        dailyLimit: 1,
        status: 'active',
        icon: 'fas fa-calendar-day',
        metadata: {
            streakBonus: true
        }
    }
];

const defaultWhitelist = [
    {
        ipAddress: '127.0.0.1',
        type: 'admin',
        reason: 'Local development',
        expiresAt: null
    },
    {
        ipAddress: '::1',
        type: 'admin',
        reason: 'Local development IPv6',
        expiresAt: null
    }
];

const initDatabase = async () => {
    try {
        logger.info('Initializing database...');
        
        // Create default tasks if they don't exist
        for (const taskData of defaultTasks) {
            const existingTask = await Task.findOne({ title: taskData.title });
            if (!existingTask) {
                await Task.create(taskData);
                logger.info(`Created task: ${taskData.title}`);
            }
        }
        
        // Create whitelist entries
        for (const whitelistData of defaultWhitelist) {
            const existingEntry = await Whitelist.findOne({ 
                ipAddress: whitelistData.ipAddress 
            });
            if (!existingEntry) {
                await Whitelist.create(whitelistData);
                logger.info(`Whitelisted IP: ${whitelistData.ipAddress}`);
            }
        }
        
        // Clean up expired blocks
        await BlockedIP.cleanupExpiredBlocks();
        
        // Create indexes if they don't exist
        await User.createIndexes();
        await Task.createIndexes();
        await BlockedIP.createIndexes();
        await Whitelist.createIndexes();
        
        logger.info('Database initialization completed');
        
        // Log database stats
        const userCount = await User.countDocuments();
        const taskCount = await Task.countDocuments();
        const blockedCount = await BlockedIP.countDocuments();
        
        logger.info(`Database Stats:
          Users: ${userCount}
          Tasks: ${taskCount}
          Blocked IPs: ${blockedCount}
        `);
        
    } catch (error) {
        logger.error('Database initialization failed:', error);
        throw error;
    }
};

module.exports = { initDatabase };
