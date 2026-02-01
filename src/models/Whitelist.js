const mongoose = require('mongoose');
const NodeCache = require('node-cache');
const logger = require('../utils/logger');

// Cache for whitelisted IPs (5 minutes TTL)
const whitelistCache = new NodeCache({ stdTTL: 300, checkperiod: 60 });

const WhitelistSchema = new mongoose.Schema({
    ipAddress: {
        type: String,
        required: true,
        unique: true,
        index: true
    },
    type: {
        type: String,
        required: true,
        enum: ['admin', 'user', 'api', 'system'],
        default: 'user'
    },
    reason: {
        type: String,
        required: true
    },
    createdBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    expiresAt: {
        type: Date,
        index: true
    },
    metadata: {
        type: Map,
        of: mongoose.Schema.Types.Mixed
    },
    isActive: {
        type: Boolean,
        default: true,
        index: true
    }
}, {
    timestamps: true
});

// Indexes
WhitelistSchema.index({ expiresAt: 1 });
WhitelistSchema.index({ type: 1, isActive: 1 });

// Pre-save middleware to update cache
WhitelistSchema.pre('save', function(next) {
    // Invalidate cache for this IP
    whitelistCache.del(this.ipAddress);
    next();
});

// Static methods
WhitelistSchema.statics.isWhitelisted = async function(ip) {
    // Check cache first
    const cached = whitelistCache.get(ip);
    if (cached !== undefined) {
        return cached;
    }
    
    const whitelistEntry = await this.findOne({
        ipAddress: ip,
        isActive: true,
        $or: [
            { expiresAt: { $gt: new Date() } },
            { expiresAt: null }
        ]
    }).lean();
    
    const isWhitelisted = !!whitelistEntry;
    
    // Cache the result
    whitelistCache.set(ip, isWhitelisted);
    
    return isWhitelisted;
};

WhitelistSchema.statics.isAdminIP = async function(ip) {
    const adminIPs = process.env.ADMIN_IP_WHITELIST 
        ? process.env.ADMIN_IP_WHITELIST.split(',') 
        : [];
    
    // Check environment variable whitelist first
    if (adminIPs.includes(ip)) {
        return true;
    }
    
    // Check database whitelist
    const whitelistEntry = await this.findOne({
        ipAddress: ip,
        type: 'admin',
        isActive: true,
        $or: [
            { expiresAt: { $gt: new Date() } },
            { expiresAt: null }
        ]
    }).lean();
    
    return !!whitelistEntry;
};

WhitelistSchema.statics.addToWhitelist = async function(ip, type, reason, options = {}) {
    const { userId, createdBy, expiresAt, metadata } = options;
    
    let whitelistEntry = await this.findOne({ ipAddress: ip });
    
    if (whitelistEntry) {
        // Update existing entry
        whitelistEntry.type = type;
        whitelistEntry.reason = reason;
        whitelistEntry.isActive = true;
        whitelistEntry.expiresAt = expiresAt || null;
        
        if (userId) whitelistEntry.userId = userId;
        if (createdBy) whitelistEntry.createdBy = createdBy;
        
        if (metadata) {
            whitelistEntry.metadata = new Map([
                ...Array.from(whitelistEntry.metadata.entries()),
                ...Object.entries(metadata)
            ]);
        }
    } else {
        // Create new entry
        whitelistEntry = new this({
            ipAddress: ip,
            type,
            reason,
            userId,
            createdBy,
            expiresAt,
            metadata: metadata ? new Map(Object.entries(metadata)) : new Map()
        });
    }
    
    await whitelistEntry.save();
    
    logger.info(`IP added to whitelist: ${ip} (${type}) - ${reason}`);
    
    return whitelistEntry;
};

WhitelistSchema.statics.removeFromWhitelist = async function(ip) {
    const result = await this.deleteOne({ ipAddress: ip });
    
    // Clear from cache
    whitelistCache.del(ip);
    
    if (result.deletedCount > 0) {
        logger.info(`IP removed from whitelist: ${ip}`);
        return true;
    }
    
    return false;
};

WhitelistSchema.statics.getWhitelist = async function() {
    return this.find({
        isActive: true,
        $or: [
            { expiresAt: { $gt: new Date() } },
            { expiresAt: null }
        ]
    })
    .sort({ type: 1, createdAt: -1 })
    .populate('createdBy', 'name email')
    .populate('userId', 'name email')
    .lean();
};

WhitelistSchema.statics.deactivate = async function(ip) {
    const result = await this.updateOne(
        { ipAddress: ip },
        { $set: { isActive: false } }
    );
    
    // Clear from cache
    whitelistCache.del(ip);
    
    if (result.modifiedCount > 0) {
        logger.info(`IP deactivated from whitelist: ${ip}`);
        return true;
    }
    
    return false;
};

WhitelistSchema.statics.cleanupExpired = async function() {
    const result = await this.updateMany(
        {
            expiresAt: { $lt: new Date() },
            isActive: true
        },
        { $set: { isActive: false } }
    );
    
    if (result.modifiedCount > 0) {
        logger.info(`Deactivated ${result.modifiedCount} expired whitelist entries`);
        
        // Clear entire cache since we don't know which IPs were affected
        whitelistCache.flushAll();
    }
    
    return result;
};

WhitelistSchema.statics.getStats = async function() {
    const stats = await this.aggregate([
        {
            $match: { isActive: true }
        },
        {
            $facet: {
                total: [{ $count: 'count' }],
                byType: [
                    {
                        $group: {
                            _id: '$type',
                            count: { $sum: 1 }
                        }
                    }
                ],
                expiringSoon: [
                    {
                        $match: {
                            expiresAt: { 
                                $gte: new Date(),
                                $lte: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
                            }
                        }
                    },
                    { $count: 'count' }
                ]
            }
        }
    ]);
    
    return {
        total: stats[0]?.total[0]?.count || 0,
        byType: stats[0]?.byType || [],
        expiringSoon: stats[0]?.expiringSoon[0]?.count || 0
    };
};

const Whitelist = mongoose.model('Whitelist', WhitelistSchema);

module.exports = Whitelist;
