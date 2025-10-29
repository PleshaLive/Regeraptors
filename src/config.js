'use strict';

const path = require('path');
const crypto = require('crypto');
const dotenv = require('dotenv');

dotenv.config();

const projectRoot = path.resolve(__dirname, '..');

const toInt = (value, fallback) => {
  if (value === undefined || value === null || value === '') {
    return fallback;
  }
  const parsed = Number.parseInt(String(value), 10);
  return Number.isNaN(parsed) ? fallback : parsed;
};

const toBool = (value, fallback = false) => {
  if (value === undefined || value === null) {
    return fallback;
  }
  const normalized = String(value).trim().toLowerCase();
  return ['1', 'true', 'yes', 'on'].includes(normalized);
};

const parseList = (value) => {
  if (!value) {
    return [];
  }
  return String(value)
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
};

const whitelist = parseList(process.env.GSI_WHITELIST);

const config = {
  nodeEnv: process.env.NODE_ENV || 'development',
  port: toInt(process.env.PORT, 3000),
  adminUser: process.env.ADMIN_USER || '',
  adminPass: process.env.ADMIN_PASS || '',
  adminOrigin: process.env.ADMIN_ORIGIN || '',
  gsiWhitelist: whitelist,
  forwardQueueEnabled: toBool(process.env.FORWARD_QUEUE, false),
  forwardFlushMs: toInt(process.env.FORWARD_FLUSH_MS, 1000),
  retryMax: Math.max(toInt(process.env.RETRY_MAX, 3), 1),
  retryBaseMs: Math.max(toInt(process.env.RETRY_BASE_MS, 500), 100),
  retryJitterMs: Math.max(toInt(process.env.RETRY_JITTER, 250), 0),
  sessionSecret:
    process.env.SESSION_SECRET && process.env.SESSION_SECRET.length >= 16
      ? process.env.SESSION_SECRET
      : crypto.randomBytes(48).toString('hex'),
  logDir: process.env.LOG_DIR || './logs',
  projectRoot,
  targetsFile: path.resolve(projectRoot, 'config', 'targets.json'),
  isProduction: (process.env.NODE_ENV || '').toLowerCase() === 'production'
};

module.exports = config;
