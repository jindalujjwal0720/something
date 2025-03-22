import fs from 'node:fs/promises';
import { ViteDevServer } from 'vite';
import path from 'node:path';

// Define the structure of the render function's return type
interface RenderResult {
  html?: string;
  head?: string;
}

// Interface for the SSR module
interface SSRModule {
  render: (url: string) => Promise<RenderResult>;
}

// Constants
const isProduction = process.env.NODE_ENV === 'production';
const base = process.env.BASE || '/';

const actualPath = (value: string) => {
  return path.join('../web', value);
};

const prodHtmlPath = actualPath('./dist/client/index.html');
const devHtmlPath = actualPath('./index.html');
const devServerPath = actualPath('./src/entry-server.tsx');
const prodServerPath = actualPath('./dist/ssr/entry-server.js');

// Cached production assets
let templateHtml = '';

// Initialize Vite server
let vite: ViteDevServer | undefined;

/**
 * Initialize the SSR module
 * @returns Promise that resolves when initialization is complete
 */
export async function initializeSSR() {
  // Load template HTML for production
  if (isProduction) {
    templateHtml = await fs.readFile(prodHtmlPath, 'utf-8');
  }

  // Initialize Vite server for development
  if (!isProduction) {
    const { createServer } = await import('vite');
    vite = await createServer({
      server: { middlewareMode: true },
      appType: 'custom',
      base,
      root: '../web',
    });
  }

  return { vite };
}

/**
 * Get the Vite middleware for development
 * @returns Vite middleware or compression/sirv middleware for production
 */
export async function getViteMiddleware() {
  if (!isProduction) {
    if (!vite) {
      throw new Error(
        'Vite server not initialized. Call initializeSSR() first.',
      );
    }
    return vite.middlewares;
  }
  return null;
}

/**
 * SSR handler middleware
 * @param req Express request
 * @param res Express response
 * @param next Express next function
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function ssrHandler(req: any, res: any, next: any) {
  try {
    const url = req.originalUrl.replace(base, '');
    const nonce = res.locals.cspNonce;

    let template: string;
    let render: (url: string) => Promise<RenderResult>;

    if (!isProduction) {
      if (!vite) {
        throw new Error(
          'Vite server not initialized. Call initializeSSR() first.',
        );
      }

      // Always read fresh template in development
      template = await fs.readFile(devHtmlPath, 'utf-8');
      template = await vite.transformIndexHtml(url, template);
      render = ((await vite.ssrLoadModule(devServerPath)) as SSRModule).render;
    } else {
      template = templateHtml;
      render = ((await import(prodServerPath)) as unknown as SSRModule).render;
    }

    const rendered = await render(url);

    let html = template
      .replace(`<!--app-head-->`, rendered.head ?? '')
      .replace(`<!--app-html-->`, rendered.html ?? '');

    // add nonce to script tags
    html = html.replace(
      /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
      (match) => {
        return match.replace('<script', `<script nonce="${nonce}"`);
      },
    );

    res.status(200).set({ 'Content-Type': 'text/html' }).send(html);
  } catch (e: unknown) {
    vite?.ssrFixStacktrace(e as Error);
    console.log((e as Error).stack);
    next(e);
  }
}

/**
 * Clean up resources when shutting down
 */
export async function closeSSR() {
  if (vite) {
    await vite.close();
  }
}
