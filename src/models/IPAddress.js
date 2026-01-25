const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database');

const IPAddress = sequelize.define('IPAddress', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true
  },
  ip_address: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true
  },
  user_count: {
    type: DataTypes.INTEGER,
    defaultValue: 0
  },
  country_code: {
    type: DataTypes.STRING
  },
  city: {
    type: DataTypes.STRING
  },
  is_blocked: {
    type: DataTypes.BOOLEAN,
    defaultValue: false
  },
  block_reason: {
    type: DataTypes.STRING
  },
  last_activity: {
    type: DataTypes.DATE
  }
}, {
  tableName: 'ip_addresses',
  timestamps: true,
  underscored: true
});

module.exports = IPAddress;
