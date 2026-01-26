const mongoose = require('mongoose');
const logger = require('../utils/logger');

const IPLogSchema = new mongoose.Schema({
    // IP Information
    ipAddress: {
        type: String,
        required: true,
        index: true
    },
    ipVersion: {
        type: Number,
        enum: [4, 6],
        default: 4
    },
    
    // User Information
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        index: true
    },
    sessionId: String,
    
    // Request Information
    action: {
        type: String,
        required: true,
        enum: [
            'signup', 'login', 'logout', 'task_completion',
            'wallet_connect', 'api_request', 'page_view',
            'blocked_attempt', 'suspicious_activity'
        ],
        index: true
    },
    endpoint: String,
    method: String,
    userAgent: String,
    referrer: String,
    
    // Geolocation
    country: String,
    countryCode: String,
    region: String,
    regionName: String,
    city: String,
    zip: String,
    lat: Number,
    lon: Number,
    timezone: String,
    isp: String,
    org: String,
    as: String,
    
    // Security Flags
    vpn: {
        type: Boolean,
        default: false
    },
    proxy: {
        type: Boolean,
        default: false
    },
    hosting: {
        type: Boolean,
        default: false
    },
    tor: {
        type: Boolean,
        default: false
    },
    
    // Risk Assessment
    riskScore: {
        type: Number,
        default: 0,
        min: 0,
        max: 100
    },
    riskFactors: [{
        type: String,
        enum: [
            'high_frequency', 'multiple_accounts', 'suspicious_pattern',
            'vpn_proxy', 'blocked_range', 'unusual_location'
        ]
    }],
    
    // Blocking Information
    isBlocked: {
        type: Boolean,
        default: false,
        index: true
    },
    blockReason: String,
    blockType: {
        type: String,
        enum: ['temporary', 'permanent', 'range']
    },
    blockExpires: {
        type: Date,
        index: true
    },
    blockDuration: Number, // in milliseconds
    
    // Response Information
    statusCode: Number,
    responseTime: Number, // in milliseconds
    responseSize: Number, // in bytes
    
    // Metadata
    headers: mongoose.Schema.Types.Mixed,
    queryParams: mongoose.Schema.Types.Mixed,
    bodyHash: String,
    
    // Timestamps
    timestamp: {
        type: Date,
        default: Date.now,
        index: true,
        expires: '90d' // Auto-delete after 90 days
    }
}, {
    timestamps: true
});

// Indexes for optimized queries
IPLogSchema.index({ ipAddress: 1, timestamp: -1 });
IPLogSchema.index({ userId: 1, timestamp: -1 });
IPLogSchema.index({ action: 1, timestamp: -1 });
IPLogSchema.index({ country: 1, timestamp: -1 });
IPLogSchema.index({ riskScore: -1, timestamp: -1 });
IPLogSchema.index({ isBlocked: 1, blockExpires: 1 });

// Static methods for IP analysis
IPLogSchema.statics.getIPStats = async function(ipAddress, hours = 24) {
    const timeAgo = new Date(Date.now() - hours * 60 * 60 * 1000);
    
    const stats = await this.aggregate([
        {
            $match: {
                ipAddress,
                timestamp: { $gte: timeAgo }
            }
        },
        {
            $group: {
                _id: '$action',
                count: { $sum: 1 },
                uniqueUsers: { $addToSet: '$userId' },
                lastTimestamp: { $max: '$timestamp' },
                avgRiskScore: { $avg: '$riskScore' }
            }
        },
        {
            $project: {
                action: '$_id',
                count: 1,
                uniqueUserCount: { $size: '$uniqueUsers' },
                lastTimestamp: 1,
                avgRiskScore: { $round: ['$avgRiskScore', 2] },
                _id: 0
            }
        },
        {
            $sort: { count: -1 }
        }
    ]);
    
    return stats;
};

IPLogSchema.statics.checkIPLimit = async function(ipAddress, maxUsers = 5) {
    const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    
    const result = await this.aggregate([
        {
            $match: {
                ipAddress,
                action: 'signup',
                timestamp: { $gte: twentyFourHoursAgo },
                isBlocked: false
            }
        },
        {
            $group: {
                _id: '$userId',
                firstSignup: { $min: '$timestamp' },
                lastSignup: { $max: '$timestamp' }
            }
        },
        {
            $count: 'userCount'
        }
    ]);
    
    const userCount = result[0]?.userCount || 0;
    
    return {
        allowed: userCount < maxUsers,
        currentCount: userCount,
        maxAllowed: maxUsers,
        canCreate: maxUsers - userCount
    };
};

IPLogSchema.statics.getRecentActivity = async function(ipAddress, limit = 50) {
    return this.find({ ipAddress })
        .sort({ timestamp: -1 })
        .limit(limit)
        .select('action userId timestamp riskScore isBlocked')
        .populate('userId', 'name email')
        .lean();
};

IPLogSchema.statics.blockIP = async function(ipAddress, reason, duration = 24 * 60 * 60 * 1000) {
    const blockExpires = new Date(Date.now() + duration);
    
    await this.updateMany(
        { ipAddress },
        {
            $set: {
                isBlocked: true,
                blockReason: reason,
                blockType: duration === 0 ? 'permanent' : 'temporary',
                blockExpires: duration === 0 ? null : blockExpires,
                blockDuration: duration
            }
        }
    );
    
    logger.warn(`IP blocked: ${ipAddress} - ${reason} (${duration}ms)`);
    
    return {
        ipAddress,
        blocked: true,
        reason,
        expires: blockExpires,
        duration
    };
};

IPLogSchema.statics.unblockIP = async function(ipAddress) {
    await this.updateMany(
        { ipAddress, isBlocked: true },
        {
            $set: { isBlocked: false },
            $unset: {
                blockReason: 1,
                blockType: 1,
                blockExpires: 1,
                blockDuration: 1
            }
        }
    );
    
    logger.info(`IP unblocked: ${ipAddress}`);
    
    return { ipAddress, unblocked: true };
};

IPLogSchema.statics.getBlockedIPs = async function() {
    return this.find({
        isBlocked: true,
        $or: [
            { blockExpires: { $gt: new Date() } },
            { blockExpires: null }
        ]
    })
    .distinct('ipAddress')
    .lean();
};

IPLogSchema.statics.cleanupExpiredBlocks = async function() {
    const result = await this.updateMany(
        {
            isBlocked: true,
            blockExpires: { $lt: new Date(), $ne: null }
        },
        {
            $set: { isBlocked: false },
            $unset: {
                blockReason: 1,
                blockType: 1,
                blockExpires: 1,
                blockDuration: 1
            }
        }
    );
    
    if (result.modifiedCount > 0) {
        logger.info(`Cleaned up ${result.modifiedCount} expired IP blocks`);
    }
    
    return result;
};

IPLogSchema.statics.analyzeIPRisk = async function(ipAddress) {
    const stats = await this.getIPStats(ipAddress, 1); // Last hour
    
    let riskScore = 0;
    const riskFactors = [];
    
    // Check for high frequency
    const totalRequests = stats.reduce((sum, stat) => sum + stat.count, 0);
    if (totalRequests > 100) {
        riskScore += 30;
        riskFactors.push('high_frequency');
    }
    
    // Check for multiple users
    const signupStat = stats.find(stat => stat.action === 'signup');
    if (signupStat && signupStat.uniqueUserCount > 2) {
        riskScore += 40;
        riskFactors.push('multiple_accounts');
    }
    
    // Check for suspicious patterns
    const suspiciousActions = ['blocked_attempt', 'suspicious_activity'];
    const suspiciousCount = stats
        .filter(stat => suspiciousActions.includes(stat.action))
        .reduce((sum, stat) => sum + stat.count, 0);
    
    if (suspiciousCount > 5) {
        riskScore += 25;
        riskFactors.push('suspicious_pattern');
    }
    
    // Check if already blocked
    const isBlocked = await this.findOne({
        ipAddress,
        isBlocked: true,
        $or: [
            { blockExpires: { $gt: new Date() } },
            { blockExpires: null }
        ]
    });
    
    if (isBlocked) {
        riskScore = 100;
        riskFactors.push('already_blocked');
    }
    
    return {
        ipAddress,
        riskScore: Math.min(riskScore, 100),
        riskFactors,
        stats
    };
};

const IPLog = mongoose.model('IPLog', IPLogSchema);

module.exports = IPLog;
