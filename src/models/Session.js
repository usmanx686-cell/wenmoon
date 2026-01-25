const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database');
const crypto = require('crypto');

const Session = sequelize.define('Session', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true
  },
  user_id: {
    type: DataTypes.INTEGER,
    allowNull: false,
    references: {
      model: 'users',
      key: 'id'
    }
  },
  session_token: {
    type: DataTypes.STRING(255),
    unique: true,
    allowNull: false
  },
  refresh_token: {
    type: DataTypes.STRING(255),
    unique: true
  },
  ip_address: {
    type: DataTypes.STRING(45)
  },
  user_agent: {
    type: DataTypes.TEXT
  },
  device_type: {
    type: DataTypes.STRING(50)
  },
  browser: {
    type: DataTypes.STRING(100)
  },
  os: {
    type: DataTypes.STRING(100)
  },
  expires_at: {
    type: DataTypes.DATE,
    allowNull: false
  },
  last_activity: {
    type: DataTypes.DATE,
    defaultValue: DataTypes.NOW
  },
  is_active: {
    type: DataTypes.BOOLEAN,
    defaultValue: true
  },
  metadata: {
    type: DataTypes.JSONB,
    defaultValue: {}
  }
}, {
  tableName: 'sessions',
  timestamps: true,
  underscored: true,
  indexes: [
    {
      fields: ['session_token'],
      unique: true
    },
    {
      fields: ['user_id']
    },
    {
      fields: ['expires_at']
    },
    {
      fields: ['is_active']
    }
  ]
});

// Static methods
Session.createSession = async function(userId, ipAddress, userAgent, metadata = {}) {
  const sessionToken = crypto.randomBytes(32).toString('hex');
  const refreshToken = crypto.randomBytes(32).toString('hex');
  
  // Parse user agent for device info
  let deviceType = 'desktop';
  let browser = 'Unknown';
  let os = 'Unknown';
  
  if (userAgent) {
    if (userAgent.includes('Mobile')) {
      deviceType = 'mobile';
    } else if (userAgent.includes('Tablet')) {
      deviceType = 'tablet';
    }
    
    // Simple browser detection
    if (userAgent.includes('Chrome')) {
      browser = 'Chrome';
    } else if (userAgent.includes('Firefox')) {
      browser = 'Firefox';
    } else if (userAgent.includes('Safari')) {
      browser = 'Safari';
    } else if (userAgent.includes('Edge')) {
      browser = 'Edge';
    }
    
    // Simple OS detection
    if (userAgent.includes('Windows')) {
      os = 'Windows';
    } else if (userAgent.includes('Mac')) {
      os = 'macOS';
    } else if (userAgent.includes('Linux')) {
      os = 'Linux';
    } else if (userAgent.includes('Android')) {
      os = 'Android';
    } else if (userAgent.includes('iPhone') || userAgent.includes('iPad')) {
      os = 'iOS';
    }
  }
  
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
  
  const session = await this.create({
    user_id: userId,
    session_token: sessionToken,
    refresh_token: refreshToken,
    ip_address: ipAddress,
    user_agent: userAgent,
    device_type: deviceType,
    browser: browser,
    os: os,
    expires_at: expiresAt,
    last_activity: new Date(),
    metadata: metadata
  });
  
  return session;
};

Session.findActiveByToken = async function(token) {
  return await this.findOne({
    where: {
      session_token: token,
      is_active: true,
      expires_at: { [sequelize.Op.gt]: new Date() }
    },
    include: [{
      association: 'user',
      attributes: ['id', 'email', 'username', 'is_active', 'is_admin']
    }]
  });
};

Session.findActiveByRefreshToken = async function(refreshToken) {
  return await this.findOne({
    where: {
      refresh_token: refreshToken,
      is_active: true,
      expires_at: { [sequelize.Op.gt]: new Date() }
    },
    include: [{
      association: 'user',
      attributes: ['id', 'email', 'username', 'is_active', 'is_admin']
    }]
  });
};

Session.findActiveByUserId = async function(userId) {
  return await this.findAll({
    where: {
      user_id: userId,
      is_active: true,
      expires_at: { [sequelize.Op.gt]: new Date() }
    },
    order: [['last_activity', 'DESC']]
  });
};

Session.invalidateSession = async function(token) {
  return await this.update(
    { is_active: false },
    { where: { session_token: token } }
  );
};

Session.invalidateAllUserSessions = async function(userId, excludeToken = null) {
  const whereClause = {
    user_id: userId,
    is_active: true
  };
  
  if (excludeToken) {
    whereClause.session_token = { [sequelize.Op.ne]: excludeToken };
  }
  
  return await this.update(
    { is_active: false },
    { where: whereClause }
  );
};

Session.cleanExpiredSessions = async function() {
  return await this.destroy({
    where: {
      expires_at: { [sequelize.Op.lt]: new Date() }
    }
  });
};

Session.updateActivity = async function(token) {
  return await this.update(
    { last_activity: new Date() },
    { where: { session_token: token, is_active: true } }
  );
};

Session.getUserSessionsCount = async function(userId) {
  return await this.count({
    where: {
      user_id: userId,
      is_active: true,
      expires_at: { [sequelize.Op.gt]: new Date() }
    }
  });
};

Session.getActiveSessions = async function(limit = 100) {
  return await this.findAll({
    where: {
      is_active: true,
      expires_at: { [sequelize.Op.gt]: new Date() }
    },
    include: [{
      association: 'user',
      attributes: ['id', 'email', 'username']
    }],
    order: [['last_activity', 'DESC']],
    limit: limit
  });
};

// Instance methods
Session.prototype.refresh = async function() {
  const newExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
  await this.update({
    expires_at: newExpiresAt,
    last_activity: new Date()
  });
  return this;
};

Session.prototype.toJSON = function() {
  const values = Object.assign({}, this.get());
  
  // Remove sensitive fields
  delete values.session_token;
  delete values.refresh_token;
  delete values.ip_address;
  delete values.user_agent;
  delete values.created_at;
  delete values.updated_at;
  delete values.metadata;
  
  // Format dates
  if (values.expires_at) {
    values.expires_at = values.expires_at.toISOString();
  }
  if (values.last_activity) {
    values.last_activity = values.last_activity.toISOString();
  }
  
  return values;
};

module.exports = Session;
