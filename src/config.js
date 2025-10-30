'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const dotenv = require('dotenv');

dotenv.config();

const projectRoot = path.resolve(__dirname, '..');

const coerceInt = (value, fallback) => {
  if (value === undefined || value === null || value === '') {
    return fallback;
  }
  const parsed = Number.parseInt(String(value), 10);
  return Number.isNaN(parsed) ? fallback : parsed;
};

const coerceBool = (value, fallback = false) => {
  if (value === undefined || value === null) {
    return fallback;
  }
  const normalised = String(value).trim().toLowerCase();
  return ['1', 'true', 'yes', 'on'].includes(normalised);
};

const toSessionSecret = (secret) => {
  if (secret && secret.length >= 16) {
    return secret;
  }
  const fallback = crypto.randomBytes(32).toString('hex');
  return fallback;
};

const ensureTargetsFile = (filePath) => {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  if (!fs.existsSync(filePath)) {
    fs.writeFileSync(filePath, '[]\n', 'utf8');
  }
};

const corsOrigin = process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.trim() : '*';
const allowedOrigins = corsOrigin === '*'
  ? []
  : corsOrigin
      .split(',')
      .map((origin) => origin.trim())
      .filter((origin) => origin.length > 0);
const targetsFile = path.resolve(projectRoot, 'config', 'targets.json');
ensureTargetsFile(targetsFile);

const sessionSecretFromEnv = Boolean(process.env.SESSION_SECRET && process.env.SESSION_SECRET.length >= 16);
const sessionSecret = toSessionSecret(process.env.SESSION_SECRET || '');

const config = {
  nodeEnv: process.env.NODE_ENV || 'development',
  port: coerceInt(process.env.PORT, 3000),
  adminUser: process.env.ADMIN_USER || '',
  adminPass: process.env.ADMIN_PASS || '',
  sessionSecret,
  sessionSecretFromEnv,
  corsOrigin,
  allowedOrigins,
  projectRoot,
  targetsFile,
  queueEnabled: coerceBool(process.env.FORWARD_QUEUE, false),
  forwardFlushMs: coerceInt(process.env.FORWARD_FLUSH_MS, 1000),
  retryMax: Math.max(coerceInt(process.env.RETRY_MAX, 3), 1),
  retryBaseMs: Math.max(coerceInt(process.env.RETRY_BASE_MS, 500), 100),
  retryJitterMs: Math.max(coerceInt(process.env.RETRY_JITTER, 250), 0),
  logLevel: (process.env.LOG_LEVEL || 'info').toLowerCase(),
  cookieSecure: allowedOrigins.length > 0 && allowedOrigins.every((origin) => origin.startsWith('https://')),
  isProduction: (process.env.NODE_ENV || '').toLowerCase() === 'production'
};

module.exports = config;
