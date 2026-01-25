const { sequelize } = require('../config/database');
const path = require('path');
const fs = require('fs');
const Sequelize = require('sequelize');
const basename = path.basename(__filename);
const db = {};

// Import all models
fs.readdirSync(__dirname)
  .filter(file => {
    return (
      file.indexOf('.') !== 0 &&
      file !== basename &&
      file.slice(-3) === '.js' &&
      file.indexOf('.test.js') === -1
    );
  })
  .forEach(file => {
    const model = require(path.join(__dirname, file));
    db[model.name] = model;
  });

// Associate models if associations exist
Object.keys(db).forEach(modelName => {
  if (db[modelName].associate) {
    db[modelName].associate(db);
  }
});

db.sequelize = sequelize;
db.Sequelize = Sequelize;

// Define associations
const { User, Task, UserTask, IPAddress, Session, ActivityLog, Referral, WalletConnection } = db;

// User associations
User.hasMany(UserTask, { foreignKey: 'user_id', as: 'completedTasks' });
User.hasMany(Session, { foreignKey: 'user_id', as: 'sessions' });
User.hasMany(ActivityLog, { foreignKey: 'user_id', as: 'activityLogs' });
User.hasMany(Referral, { foreignKey: 'referrer_id', as: 'referralsMade' });
User.hasMany(Referral, { foreignKey: 'referred_id', as: 'referralsReceived' });
User.hasMany(WalletConnection, { foreignKey: 'user_id', as: 'wallets' });

// Task associations
Task.hasMany(UserTask, { foreignKey: 'task_id', sourceKey: 'task_id', as: 'completions' });

// UserTask associations
UserTask.belongsTo(User, { foreignKey: 'user_id', as: 'user' });
UserTask.belongsTo(Task, { foreignKey: 'task_id', targetKey: 'task_id', as: 'task' });

// Session associations
Session.belongsTo(User, { foreignKey: 'user_id', as: 'user' });

// ActivityLog associations
ActivityLog.belongsTo(User, { foreignKey: 'user_id', as: 'user' });

// Referral associations
Referral.belongsTo(User, { foreignKey: 'referrer_id', as: 'referrer' });
Referral.belongsTo(User, { foreignKey: 'referred_id', as: 'referred' });

// WalletConnection associations
WalletConnection.belongsTo(User, { foreignKey: 'user_id', as: 'user' });

module.exports = db;
