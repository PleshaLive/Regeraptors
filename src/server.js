'use strict';

const http = require('http');
const path = require('path');
const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
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
let lastGsiTimestamp = null;

const allowedOrigins = config.allowedOrigins.length ? config.allowedOrigins : null;

const buildCors = (credentials) => {
  if (!allowedOrigins) {
    return credentials
      ? (req, _res, next) => next()
      : cors();
  }

  return cors({
    origin: (origin, callback) => {
      if (!origin) {
        callback(null, true);
        return;
      }
      const allowed = allowedOrigins.includes(origin);
      callback(allowed ? null : new Error('Not allowed by CORS'), allowed);
    },
    credentials
  });
};

const adminCors = buildCors(true);
const gsiCors = buildCors(false);

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
    secure: Boolean(config.cookieSecure),
    maxAge: 24 * 60 * 60 * 1000
  }
});

app.disable('x-powered-by');
app.set('trust proxy', 1);

app.use(helmet());
app.use(compression());
app.use(express.json({ limit: '1mb' }));
app.use('/admin', sessionMiddleware);
app.use('/admin/api', adminLimiter);

const requireAdmin = (req, res, next) => {
  if (req.session && req.session.authenticated) {
    next();
    return;
  }
  res.status(StatusCodes.UNAUTHORIZED).json({ error: 'Authentication required' });
};

app.get('/healthz', (_req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

app.get('/readyz', (_req, res) => {
  res.json({
    status: 'ok',
    targetsLoaded: targetManager.getSnapshot().length,
    queueEnabled: config.queueEnabled
  });
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
  req.session.destroy((error) => {
    if (error) {
      logger.error({ msg: 'Session destroy failed', error: error.message });
      res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ error: 'Logout failed' });
      return;
    }
    res.json({ status: 'ok' });
  });
});

app.get('/admin/api/config', adminCors, requireAdmin, (_req, res) => {
  res.json({
    queueEnabled: config.queueEnabled,
    forwardFlushMs: config.forwardFlushMs,
    retryMax: config.retryMax,
    retryBaseMs: config.retryBaseMs,
    retryJitterMs: config.retryJitterMs
  });
});

app.get('/admin/api/targets', adminCors, requireAdmin, (_req, res) => {
  res.json(targetManager.getSnapshot());
});

app.post('/admin/api/targets', adminCors, requireAdmin, async (req, res) => {
  const { url, enabled = true } = req.body || {};
  if (!url) {
    res.status(StatusCodes.BAD_REQUEST).json({ error: 'Target url is required' });
    return;
  }
  let parsed;
  try {
    parsed = new URL(url);
  } catch (_error) {
    res.status(StatusCodes.BAD_REQUEST).json({ error: 'Invalid URL' });
    return;
  }
  if (!['http:', 'https:', 'ws:', 'wss:'].includes(parsed.protocol)) {
    res.status(StatusCodes.BAD_REQUEST).json({ error: 'Unsupported target protocol' });
    return;
  }
  try {
    const target = await targetManager.addTarget({ url: parsed.toString(), enabled: Boolean(enabled) });
    res.status(StatusCodes.CREATED).json(target);
  } catch (error) {
    logger.error({ msg: 'Failed to add target', error: error.message });
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ error: 'Failed to add target' });
  }
});

app.patch('/admin/api/targets/:id', adminCors, requireAdmin, async (req, res) => {
  const { id } = req.params;
  if (!Object.prototype.hasOwnProperty.call(req.body || {}, 'enabled')) {
    res.status(StatusCodes.BAD_REQUEST).json({ error: 'enabled is required' });
    return;
  }
  try {
    const updated = await targetManager.updateTarget(id, { enabled: Boolean(req.body.enabled) });
    res.json(updated);
  } catch (error) {
    if (error.message === 'Target not found') {
      res.status(StatusCodes.NOT_FOUND).json({ error: 'Target not found' });
      return;
    }
    logger.error({ msg: 'Failed to update target', error: error.message });
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ error: 'Failed to update target' });
  }
});

app.delete('/admin/api/targets/:id', adminCors, requireAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    await targetManager.removeTarget(id);
    res.status(StatusCodes.NO_CONTENT).end();
  } catch (error) {
    if (error.message === 'Target not found') {
      res.status(StatusCodes.NOT_FOUND).json({ error: 'Target not found' });
      return;
    }
    logger.error({ msg: 'Failed to remove target', error: error.message });
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ error: 'Failed to remove target' });
  }
});

app.post('/admin/api/targets/:id/test', adminCors, requireAdmin, async (req, res) => {
  const target = targetManager.getById(req.params.id);
  if (!target) {
    res.status(StatusCodes.NOT_FOUND).json({ error: 'Target not found' });
    return;
  }
  try {
    const samplePayload = { type: 'gsi-test', timestamp: new Date().toISOString() };
    const result = await forwarder.testTarget(target, samplePayload);
    res.json({ latencyMs: result.latencyMs });
  } catch (error) {
    res.status(StatusCodes.BAD_GATEWAY).json({ error: error.message });
  }
});

app.use('/admin/static', express.static(path.join(config.projectRoot, 'public')));

app.get('/admin', (_req, res) => {
  res.sendFile(path.join(config.projectRoot, 'public', 'admin.html'));
});

app.options('/api/gsi', gsiCors, (_req, res) => {
  res.sendStatus(StatusCodes.NO_CONTENT);
});

app.post('/api/gsi', gsiCors, gsiLimiter, async (req, res) => {
  if (!req.is('application/json')) {
    res.status(StatusCodes.BAD_REQUEST).json({ error: 'Expected application/json' });
    return;
  }
  const payload = req.body;
  if (!validateGsi(payload)) {
    res.status(StatusCodes.BAD_REQUEST).json({ error: 'Invalid GSI payload' });
    return;
  }
  lastGsiState = payload;
  lastGsiTimestamp = new Date().toISOString();
  broadcastGsi(payload);
  forwarder.handleUpdate(payload).catch((error) => {
    logger.error({ msg: 'Forwarding pipeline error', error: error.message });
  });
  res.status(StatusCodes.NO_CONTENT).end();
});

app.use((req, res) => {
  res.status(StatusCodes.NOT_FOUND).json({ error: 'Not found' });
});

app.use((error, req, res, next) => {
  if (error && error.message === 'Not allowed by CORS') {
    res.status(StatusCodes.FORBIDDEN).json({ error: 'Not allowed by CORS' });
    return;
  }
  next(error);
});

app.use((error, _req, res, _next) => {
  logger.error({ msg: 'Unhandled error', error: error.message, stack: error.stack });
  res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ error: 'Internal server error' });
});

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
        timestamp: lastGsiTimestamp || new Date().toISOString()
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

const shutdown = (signal) => {
  logger.info({ msg: 'Shutting down', signal });
  clearInterval(pingInterval);
  forwarder.stop();
  wss.close();
  server.close(() => process.exit(0));
  setTimeout(() => {
    logger.error({ msg: 'Forced shutdown after timeout' });
    process.exit(1);
  }, 10000).unref();
};

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('unhandledRejection', (reason) => {
  logger.error({ msg: 'Unhandled rejection', reason: reason instanceof Error ? reason.message : reason });
});
process.on('uncaughtException', (error) => {
  logger.error({ msg: 'Uncaught exception', error: error.message, stack: error.stack });
  shutdown('uncaughtException');
});

const start = async () => {
  try {
    await targetManager.init();
    forwarder.start();
    if (!config.sessionSecretFromEnv) {
      logger.warn({ msg: 'SESSION_SECRET not provided via environment; sessions will reset on restart' });
    }
    server.listen(config.port, () => {
      logger.info({ msg: 'Server listening', port: config.port });
    });
  } catch (error) {
    logger.error({ msg: 'Failed to start server', error: error.message });
    process.exit(1);
  }
};

start();
