import express, { Response } from 'express';
import cookieParser from 'cookie-parser';
import { env } from '../config';
import helmet from 'helmet';
import compression from 'compression';
import api from '../api';
import { logger } from '../utils/logger';
import * as useragent from 'express-useragent';
import { UserAgentMiddleware } from '../api/middlewares/user-agent';
import crypto from 'crypto';

const expressLoader = async ({ app }: { app: express.Application }) => {
  app.get('/status', (req, res) => {
    res.status(200).end();
  });
  app.head('/status', (req, res) => {
    res.status(200).end();
  });

  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  app.use(cookieParser());

  // Set security headers
  // 1. Content Security Policy with a nonce
  app.use((req, res, next) => {
    res.locals.cspNonce = crypto.randomBytes(16).toString('hex');
    next();
  });
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          scriptSrc: [
            "'self'",
            (req, res) => `'nonce-${(res as Response).locals.cspNonce}'`,
          ],
          connectSrc:
            env.nodeEnv !== 'production'
              ? [
                  "'self'",
                  'ws://localhost:24678', // vite dev
                ]
              : ["'self'", env.client.url],
        },
      },
    }),
  );
  // Compress response bodies for all requests
  // to reduce the network latency and bandwidth usage
  app.use(compression());
  // Parse user-agent header
  app.use(useragent.express());
  const userAgentMiddleware = new UserAgentMiddleware();
  app.use(userAgentMiddleware.extractDeviceInfo);

  app.get('/device', (req, res) => {
    res.json({
      browser: req.useragent?.browser,
      os: req.useragent?.os,
      platform: req.useragent?.platform,
      source: req.useragent?.source,
    });
  });

  // Request logging
  if (env.nodeEnv === 'development') {
    app.use('/api', (req, _res, next) => {
      logger.http(`${req.method} ${req.originalUrl}`);
      next();
    });
  }

  // Load all routes
  app.use('/api/v1', api);
};

export default expressLoader;
