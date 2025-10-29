'use strict';

const http = require('http');
const path = require('path');
const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const requestId = require('express-request-id')();
const Ajv = require('ajv');
const addFormats = require('ajv-formats');
const { StatusCodes } = require('http-status-codes');
const { WebSocketServer } = require('ws');
const config = require('./config');
const logger = require('./logger');
const TargetManager = require('./target-manager');
const Forwarder = require('./forwarder');

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ noServer: true });
const targetManager = new TargetManager();
const forwarder = new Forwarder(targetManager);
const ajv = new Ajv({ allErrors: true, allowUnionTypes: true });
addFormats(ajv);

const gsiSchema = {
  type: 'object',
  additionalProperties: true,
  required: ['provider'],
  properties: {
    provider: {
      type: 'object',
      required: ['name', 'appid'],
      additionalProperties: true,
      properties: {
        name: { type: 'string' },
        appid: { type: ['integer', 'string'] }
      }
    }
  }
};

const validateGsi = ajv.compile(gsiSchema);

let lastGsiState = null;
let lastGsiAt = null;

function broadcastGsi(payload) {
  if (!payload) {
    return;
  }
  const message = JSON.stringify({
    type: 'gsi-update',
    payload,
    timestamp: new Date().toISOString()
  });
  wss.clients.forEach((client) => {
    if (client.readyState === client.OPEN) {
      client.send(message);
    }
  });
}

const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false
});

const gsiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false
});

const sessionMiddleware = session({
  name: 'gsi.sid',
  secret: config.sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: config.isProduction,
    maxAge: 24 * 60 * 60 * 1000
  }
});

app.set('trust proxy', 1);
app.disable('x-powered-by');

app.use(requestId);
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'same-origin' }
}));
app.use(compression());
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));
app.use((req, res, next) => {
  const start = process.hrtime.bigint();
  res.on('finish', () => {
    const diff = Number(process.hrtime.bigint() - start) / 1_000_000;
    logger.info({
      msg: 'request.completed',
      method: req.method,
      url: req.originalUrl,
      statusCode: res.statusCode,
      durationMs: Number(diff.toFixed(3)),
      requestId: req.id,
      ip: req.ip
    });
  });
  next();
});

app.use('/admin', sessionMiddleware);
app.use('/admin/api', adminLimiter);

const allowedAdminOrigins = config.adminOrigin
  .split(',')
  .map((value) => value.trim())
  .filter((value) => value.length);

const allowAdminCors = (req, callback) => {
  if (!allowedAdminOrigins.length) {
    callback(null, true);
    return;
  }
  const origin = req.header('Origin');
  if (!origin) {
    callback(null, true);
    return;
  }
  const allowed = allowedAdminOrigins.includes(origin);
  callback(allowed ? null : new Error('Not allowed by CORS'), allowed);
};

const adminCors = cors({ origin: allowAdminCors, credentials: true });

const sanitizeIp = (value) => {
  if (!value) {
    return '';
  }
  return value.replace('::ffff:', '');
};

const gsiWhitelistSet = new Set(config.gsiWhitelist.map((entry) => entry.toLowerCase()));

const gsiCors = cors({
  origin: (origin, callback) => {
    if (!origin) {
      callback(null, true);
      return;
    }
    if (gsiWhitelistSet.has('*')) {
      callback(null, true);
      return;
    }
    try {
      const hostname = new URL(origin).hostname.toLowerCase();
      callback(gsiWhitelistSet.has(hostname) ? null : new Error('Not allowed by CORS'), gsiWhitelistSet.has(hostname));
    } catch (error) {
      logger.debug({ msg: 'Failed to parse origin for CORS', origin, error: error.message });
      callback(new Error('Invalid origin'), false);
    }
  }
});

const gsiAccessGuard = (req, res, next) => {
  if (!config.gsiWhitelist.length) {
    next();
    return;
  }
  const remote = sanitizeIp(req.ip).toLowerCase();
  if (gsiWhitelistSet.has(remote) || gsiWhitelistSet.has('*')) {
    next();
    return;
  }
  const origin = req.get('origin');
  if (origin) {
    try {
      const hostname = new URL(origin).hostname.toLowerCase();
      if (gsiWhitelistSet.has(hostname)) {
        next();
        return;
      }
    } catch (error) {
      logger.debug({ msg: 'Failed to parse origin for whitelist check', origin, error: error.message });
    }
  }
  logger.warn({ msg: 'GSI request blocked by whitelist', remote, origin: origin || null });
  res.status(StatusCodes.FORBIDDEN).json({ error: 'Access denied' });
};

const requireAdmin = (req, res, next) => {
  if (req.session && req.session.authenticated) {
    next();
    return;
  }
  res.status(StatusCodes.UNAUTHORIZED).json({ error: 'Authentication required' });
};

app.post('/api/gsi', gsiCors, gsiLimiter, gsiAccessGuard, (req, res) => {
  if (!req.is('application/json')) {
    res.status(StatusCodes.BAD_REQUEST).json({ error: 'Expected application/json' });
    return;
  }
  const payload = req.body;
  if (!validateGsi(payload)) {
    res.status(StatusCodes.BAD_REQUEST).json({
      error: 'Invalid GSI payload',
      details: validateGsi.errors
    });
    return;
  }
  lastGsiState = payload;
  lastGsiAt = new Date().toISOString();
  broadcastGsi(payload);
  forwarder.handleUpdate(payload).catch((error) => {
    logger.error({ msg: 'Forwarding pipeline error', error: error.message, stack: error.stack });
  });
  res.status(StatusCodes.ACCEPTED).json({ status: 'queued' });
});

app.options('/api/gsi', gsiCors, (req, res) => {
  res.sendStatus(StatusCodes.NO_CONTENT);
});

app.get('/admin/api/session', adminCors, (req, res) => {
  res.json({ authenticated: Boolean(req.session && req.session.authenticated) });
});

app.post('/admin/api/login', adminCors, (req, res) => {
  const { username, password } = req.body || {};
  if (!config.adminUser || !config.adminPass) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ error: 'Admin credentials not configured' });
    return;
  }
  if (username === config.adminUser && password === config.adminPass) {
    req.session.authenticated = true;
    res.json({ status: 'ok' });
    return;
  }
  res.status(StatusCodes.UNAUTHORIZED).json({ error: 'Invalid credentials' });
});

app.post('/admin/api/logout', adminCors, requireAdmin, (req, res) => {
  req.session.destroy(() => {
    res.json({ status: 'ok' });
  });
});

app.get('/admin/api/config', adminCors, requireAdmin, (req, res) => {
  res.json({
    queueEnabled: config.forwardQueueEnabled,
    forwardFlushMs: config.forwardFlushMs,
    retryMax: config.retryMax,
    retryBaseMs: config.retryBaseMs,
    retryJitterMs: config.retryJitterMs
  });
});

app.get('/admin/api/targets', adminCors, requireAdmin, (req, res) => {
  res.json(targetManager.getSnapshot());
});

app.post('/admin/api/targets', adminCors, requireAdmin, async (req, res, next) => {
  try {
    const { url, enabled = true } = req.body || {};
    if (!url) {
      res.status(StatusCodes.BAD_REQUEST).json({ error: 'Target url is required' });
      return;
    }
    let parsed;
    try {
      parsed = new URL(url);
    } catch (error) {
      res.status(StatusCodes.BAD_REQUEST).json({ error: 'Invalid URL' });
      return;
    }
    if (!['http:', 'https:', 'ws:', 'wss:'].includes(parsed.protocol)) {
      res.status(StatusCodes.BAD_REQUEST).json({ error: 'Unsupported target protocol' });
      return;
    }
    const target = await targetManager.addTarget({ url: parsed.toString(), enabled: Boolean(enabled) });
    res.status(StatusCodes.CREATED).json(target);
  } catch (error) {
    next(error);
  }
});

app.patch('/admin/api/targets/:id', adminCors, requireAdmin, async (req, res, next) => {
  try {
    const { id } = req.params;
    const updates = {};
    if (Object.prototype.hasOwnProperty.call(req.body || {}, 'enabled')) {
      updates.enabled = Boolean(req.body.enabled);
    }
    if (req.body && req.body.url) {
      let parsed;
      try {
        parsed = new URL(req.body.url);
      } catch (error) {
        res.status(StatusCodes.BAD_REQUEST).json({ error: 'Invalid URL' });
        return;
      }
      if (!['http:', 'https:', 'ws:', 'wss:'].includes(parsed.protocol)) {
        res.status(StatusCodes.BAD_REQUEST).json({ error: 'Unsupported target protocol' });
        return;
      }
      updates.url = parsed.toString();
    }
    const updated = await targetManager.updateTarget(id, updates);
    res.json(updated);
  } catch (error) {
    if (error.message === 'Target not found') {
      res.status(StatusCodes.NOT_FOUND).json({ error: 'Target not found' });
      return;
    }
    next(error);
  }
});

app.delete('/admin/api/targets/:id', adminCors, requireAdmin, async (req, res, next) => {
  try {
    const { id } = req.params;
    await targetManager.removeTarget(id);
    res.status(StatusCodes.NO_CONTENT).end();
  } catch (error) {
    if (error.message === 'Target not found') {
      res.status(StatusCodes.NOT_FOUND).json({ error: 'Target not found' });
      return;
    }
    next(error);
  }
});

app.post('/admin/api/targets/:id/test', adminCors, requireAdmin, async (req, res, next) => {
  try {
    const { id } = req.params;
    const target = targetManager.getById(id);
    if (!target) {
      res.status(StatusCodes.NOT_FOUND).json({ error: 'Target not found' });
      return;
    }
    const result = await forwarder.testTarget(target, { type: 'gsi-test', timestamp: new Date().toISOString() });
    res.json({ status: 'ok', latencyMs: result.latencyMs });
  } catch (error) {
    res.status(StatusCodes.BAD_GATEWAY).json({ error: error.message });
  }
});

app.get('/healthz', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

app.get('/readyz', (req, res) => {
  res.json({
    status: 'ok',
    targetsLoaded: targetManager.getSnapshot().length,
    queueEnabled: config.forwardQueueEnabled
  });
});

app.use(
  '/admin/static',
  express.static(path.join(config.projectRoot, 'public'), {
    maxAge: '15m',
    etag: true,
    fallthrough: true
  })
);

app.get('/admin', (req, res) => {
  res.sendFile(path.join(config.projectRoot, 'public', 'admin.html'));
});

app.use((req, res) => {
  res.status(StatusCodes.NOT_FOUND).json({ error: 'Not found' });
});

app.use((err, req, res, _next) => {
  logger.error({
    msg: 'Unhandled error',
    error: err.message,
    stack: err.stack,
    requestId: req.id
  });
  res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ error: 'Internal server error', requestId: req.id });
});

wss.on('connection', (socket) => {
  socket.isAlive = true;
  socket.on('pong', () => {
    socket.isAlive = true;
  });
  socket.on('error', (error) => {
    logger.warn({ msg: 'WebSocket client error', error: error.message });
  });
  if (lastGsiState) {
    socket.send(
      JSON.stringify({
        type: 'gsi-update',
        payload: lastGsiState,
        timestamp: lastGsiAt || new Date().toISOString()
      })
    );
  }
});

const pingInterval = setInterval(() => {
  wss.clients.forEach((client) => {
    if (!client.isAlive) {
      client.terminate();
      return;
    }
    client.isAlive = false;
    client.ping();
  });
}, 30000);

if (typeof pingInterval.unref === 'function') {
  pingInterval.unref();
}

server.on('upgrade', (req, socket, head) => {
  if (req.url !== '/ws') {
    socket.destroy();
    return;
  }
  wss.handleUpgrade(req, socket, head, (ws) => {
    wss.emit('connection', ws, req);
  });
});

const shutdown = async (signal) => {
  logger.info({ msg: 'Shutting down', signal });
  clearInterval(pingInterval);
  forwarder.stop();
  wss.close();
  server.close(() => {
    process.exit(0);
  });
  setTimeout(() => {
    logger.error({ msg: 'Forced shutdown after timeout' });
    process.exit(1);
  }, 10000).unref();
};

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

process.on('uncaughtException', (error) => {
  logger.error({ msg: 'Uncaught exception', error: error.message, stack: error.stack });
  shutdown('uncaughtException');
});

process.on('unhandledRejection', (reason) => {
  logger.error({ msg: 'Unhandled rejection', reason: reason instanceof Error ? reason.message : reason });
});

const start = async () => {
  try {
    await targetManager.init();
    forwarder.start();
    if (!config.adminUser || !config.adminPass) {
      logger.warn({ msg: 'Admin credentials are not configured; login will be disabled' });
    }
    server.listen(config.port, () => {
      logger.info({ msg: 'Server listening', port: config.port });
    });
  } catch (error) {
    logger.error({ msg: 'Failed to start server', error: error.message, stack: error.stack });
    process.exit(1);
  }
};

start();
