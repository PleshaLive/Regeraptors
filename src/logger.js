'use strict';

const { createLogger, format, transports } = require('winston');
const config = require('./config');

const logger = createLogger({
  level: config.logLevel || 'info',
  format: format.combine(
    format.timestamp(),
    format.errors({ stack: true }),
    format.splat(),
    format.json()
  ),
  defaultMeta: {
    service: 'cs2-gsi-forwarder',
    environment: config.nodeEnv
  },
  transports: [new transports.Console({ handleExceptions: true })]
});

module.exports = logger;
