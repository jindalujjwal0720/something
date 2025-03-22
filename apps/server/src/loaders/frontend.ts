import * as express from 'express';
import {
  initializeSSR,
  getViteMiddleware,
  ssrHandler,
} from '../../../web/ssr-module';
import path from 'path';
import { env } from '../config';
import sirv from 'sirv';

interface FrontendLoaderProps {
  app: express.Application;
}

export const frontendLoader = async ({ app }: FrontendLoaderProps) => {
  // Initialize SSR
  await initializeSSR();

  // Add Vite or respective production middlewares
  const middleware = await getViteMiddleware();
  if (middleware) app.use(middleware);

  // Serve static files
  if (env.nodeEnv !== 'production') {
    app.use(express.static(path.resolve('../../../web/public')));
  } else {
    const assets = sirv(path.resolve('./dist/web/dist/client'), {
      maxAge: 7 * 24 * 60 * 60, // 1 week
      immutable: true,
    });
    app.use(assets);
  }

  // Use the SSR handler for all routes
  app.use('*', ssrHandler);
};
