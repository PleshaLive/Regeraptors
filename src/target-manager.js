'use strict';

const fs = require('fs/promises');
const path = require('path');
const crypto = require('crypto');
const { EventEmitter } = require('events');
const config = require('./config');
const logger = require('./logger');

const ensureMetricsShape = (metrics = {}) => {
  const base = {
    sent: 0,
    failed: 0,
    avgLatencyMs: 0,
    lastLatencyMs: null,
    lastStatus: null,
    lastError: null,
    lastAttemptAt: null
  };
  return { ...base, ...metrics };
};

class TargetManager extends EventEmitter {
  constructor(filePath = config.targetsFile) {
    super();
    this.filePath = filePath;
    this.targets = [];
    this.metricsMap = new Map();
    this.writeLock = Promise.resolve();
  }

  async init() {
    const resolvedPath = path.resolve(this.filePath);
    let mutated = false;
    try {
      const raw = await fs.readFile(resolvedPath, 'utf8');
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        this.targets = parsed.map((target) => {
          const id = target.id || crypto.randomUUID();
          if (!target.id) {
            mutated = true;
          }
          return {
            id,
            url: target.url,
            enabled: target.enabled !== false
          };
        });
      } else if (parsed && Array.isArray(parsed.targets)) {
        this.targets = parsed.targets.map((target) => {
          const id = target.id || crypto.randomUUID();
          if (!target.id) {
            mutated = true;
          }
          return {
            id,
            url: target.url,
            enabled: target.enabled !== false
          };
        });
      }
    } catch (error) {
      if (error.code === 'ENOENT') {
        logger.warn({ msg: 'Targets file not found, bootstrapping empty set', filePath: resolvedPath });
        await fs.writeFile(resolvedPath, '[]\n', 'utf8');
      } else {
        logger.error({ msg: 'Failed to read targets file', error: error.message, stack: error.stack });
        throw error;
      }
    }
    logger.info({ msg: 'Target manager initialized', count: this.targets.length });
    if (mutated) {
      await this._persist();
    }
  }

  getSnapshot() {
    return this.targets.map((target) => ({
      ...target,
      metrics: { ...this._metricsFor(target.id) }
    }));
  }

  getById(targetId) {
    return this.targets.find((target) => target.id === targetId) || null;
  }

  async addTarget({ url, enabled = true }) {
    const newTarget = {
      id: crypto.randomUUID(),
      url,
      enabled: Boolean(enabled)
    };
    this.targets.push(newTarget);
    this._metricsFor(newTarget.id);
    await this._persist();
    this.emit('updated', this.getSnapshot());
    return { ...newTarget, metrics: { ...this._metricsFor(newTarget.id) } };
  }

  async updateTarget(targetId, updates) {
    const target = this.getById(targetId);
    if (!target) {
      throw new Error('Target not found');
    }
    if (updates.url) {
      target.url = updates.url;
    }
    if (Object.prototype.hasOwnProperty.call(updates, 'enabled')) {
      target.enabled = Boolean(updates.enabled);
    }
    await this._persist();
    this.emit('updated', this.getSnapshot());
    return { ...target, metrics: { ...this._metricsFor(target.id) } };
  }

  async removeTarget(targetId) {
    const index = this.targets.findIndex((target) => target.id === targetId);
    if (index === -1) {
      throw new Error('Target not found');
    }
    const [removed] = this.targets.splice(index, 1);
    this.metricsMap.delete(targetId);
    await this._persist();
    this.emit('updated', this.getSnapshot());
    return removed;
  }

  recordSuccess(targetId, latencyMs) {
    const metrics = this._metricsFor(targetId);
    metrics.sent += 1;
    metrics.lastLatencyMs = latencyMs;
    metrics.lastStatus = 'ok';
    metrics.lastError = null;
    metrics.lastAttemptAt = new Date().toISOString();
    const totalSamples = metrics.sent;
    const previousAvg = metrics.avgLatencyMs;
    metrics.avgLatencyMs = previousAvg + (latencyMs - previousAvg) / totalSamples;
    this.metricsMap.set(targetId, metrics);
    this.emit('metrics', { id: targetId, metrics: { ...metrics } });
  }

  recordFailure(targetId, error) {
    const metrics = this._metricsFor(targetId);
    metrics.failed += 1;
    metrics.lastStatus = 'error';
    metrics.lastLatencyMs = null;
    metrics.lastError = error instanceof Error ? error.message : String(error);
    metrics.lastAttemptAt = new Date().toISOString();
    this.metricsMap.set(targetId, metrics);
    this.emit('metrics', { id: targetId, metrics: { ...metrics } });
  }

  resetMetrics(targetId) {
    if (targetId) {
      this.metricsMap.delete(targetId);
    } else {
      this.metricsMap.clear();
    }
    this.emit('metrics', { id: targetId || null });
  }

  _metricsFor(targetId) {
    if (!this.metricsMap.has(targetId)) {
      this.metricsMap.set(targetId, ensureMetricsShape());
    }
    return this.metricsMap.get(targetId);
  }

  async _persist() {
    const payload = JSON.stringify(this.targets, null, 2);
    this.writeLock = this.writeLock.then(() => fs.writeFile(this.filePath, `${payload}\n`, 'utf8'));
    await this.writeLock;
  }
}

module.exports = TargetManager;
