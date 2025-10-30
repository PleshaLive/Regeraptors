'use strict';

const { performance } = require('perf_hooks');
const axios = require('axios');
const { WebSocket } = require('ws');
const logger = require('./logger');
const config = require('./config');

const HTTP_TIMEOUT_MS = 7000;
const WS_HANDSHAKE_TIMEOUT_MS = 5000;

const sleep = (ms) =>
  new Promise((resolve) => {
    setTimeout(resolve, ms);
  });

class Forwarder {
  constructor(targetManager) {
    this.targetManager = targetManager;
  this.queueEnabled = config.queueEnabled;
    this.flushMs = config.forwardFlushMs;
    this.pendingUpdate = null;
    this.dispatchChain = Promise.resolve();
    this.flushTimer = null;
  }

  start() {
    if (this.queueEnabled && !this.flushTimer) {
      this.flushTimer = setInterval(() => {
        this._flushQueue().catch((error) => {
          logger.error({ msg: 'Queue flush failed', error: error.message, stack: error.stack });
        });
      }, this.flushMs);
      if (typeof this.flushTimer.unref === 'function') {
        this.flushTimer.unref();
      }
    }
  }

  stop() {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
  }

  async handleUpdate(payload) {
    if (this.queueEnabled) {
      this.pendingUpdate = payload;
      return;
    }
    this.dispatchChain = this.dispatchChain
      .then(() => this._dispatchNow(payload))
      .catch((error) => {
        logger.error({ msg: 'Dispatch chain error', error: error.message, stack: error.stack });
      });
    return this.dispatchChain;
  }

  async testTarget(target, samplePayload) {
    return this._sendWithRetry(target, samplePayload, { maxAttempts: 2, skipMetrics: true });
  }

  async _flushQueue() {
    if (!this.pendingUpdate) {
      return;
    }
    const payload = this.pendingUpdate;
    this.pendingUpdate = null;
    this.dispatchChain = this.dispatchChain
      .then(() => this._dispatchNow(payload))
      .catch((error) => {
        logger.error({ msg: 'Queued dispatch error', error: error.message, stack: error.stack });
      });
    await this.dispatchChain;
  }

  async _dispatchNow(payload) {
    const targets = this.targetManager
      .getSnapshot()
      .filter((target) => target.enabled);

    if (!targets.length) {
      return;
    }

    await Promise.all(
      targets.map(async (target) => {
        try {
          await this._sendWithRetry(target, payload);
        } catch (error) {
          logger.warn({
            msg: 'Forwarding failed after retries',
            targetId: target.id,
            targetUrl: target.url,
            error: error.message
          });
        }
      })
    );
  }

  async _sendWithRetry(target, payload, options = {}) {
    const maxAttempts = options.maxAttempts || config.retryMax;
    const jitter = config.retryJitterMs;
    let delay = config.retryBaseMs;
    let lastError = null;

    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      try {
        const latencyMs = await this._sendOnce(target, payload);
        if (!options.skipMetrics) {
          this.targetManager.recordSuccess(target.id, latencyMs);
        }
        return { success: true, latencyMs };
      } catch (error) {
        lastError = error;
        if (!options.skipMetrics) {
          this.targetManager.recordFailure(target.id, error);
        }
        if (attempt >= maxAttempts) {
          break;
        }
        const jitterMs = jitter ? Math.floor(Math.random() * jitter) : 0;
        const waitMs = delay + jitterMs;
        logger.debug({
          msg: 'Retrying target forward',
          targetId: target.id,
          attempt,
          waitMs
        });
        await sleep(waitMs);
        delay *= 2;
      }
    }

    const errorMessage = lastError instanceof Error ? lastError.message : String(lastError);
    throw new Error(errorMessage);
  }

  async _sendOnce(target, payload) {
    const url = target.url;
    const protocol = url.split(':')[0];
    const started = performance.now();
    const data = typeof payload === 'string' ? payload : JSON.stringify(payload);

    if (protocol === 'http' || protocol === 'https') {
      const response = await axios.post(url, payload, {
        headers: { 'Content-Type': 'application/json' },
        timeout: HTTP_TIMEOUT_MS,
        validateStatus: () => true
      });
      if (response.status >= 400) {
        throw new Error(`HTTP target responded with status ${response.status}`);
      }
      return performance.now() - started;
    }

    if (protocol === 'ws' || protocol === 'wss') {
      return this._sendViaWebSocket(url, data, started);
    }

    throw new Error(`Unsupported protocol for target: ${protocol}`);
  }

  async _sendViaWebSocket(url, data, started) {
    return new Promise((resolve, reject) => {
      let settled = false;
      const ws = new WebSocket(url, {
        handshakeTimeout: WS_HANDSHAKE_TIMEOUT_MS
      });
      const timeout = setTimeout(() => {
        if (!settled) {
          cleanup(new Error('WebSocket send timed out'));
        }
      }, HTTP_TIMEOUT_MS);
      if (typeof timeout.unref === 'function') {
        timeout.unref();
      }

      const cleanup = (error) => {
        if (!settled && error) {
          settled = true;
          reject(error);
        } else if (!settled) {
          settled = true;
          resolve(performance.now() - started);
        }
        clearTimeout(timeout);
        ws.removeAllListeners();
      };

      ws.on('open', () => {
        ws.send(data, (err) => {
          if (err) {
            cleanup(err);
            return;
          }
          ws.close(1000);
          cleanup();
        });
      });

      ws.on('error', (err) => {
        cleanup(err);
      });

      ws.on('close', (code) => {
        if (!settled) {
          if (code !== 1000) {
            cleanup(new Error(`WebSocket closed with code ${code}`));
          } else {
            cleanup();
          }
        }
      });

      ws.on('unexpected-response', (_req, res) => {
        cleanup(new Error(`Unexpected WS response: ${res.statusCode}`));
      });
    });
  }
}

module.exports = Forwarder;
