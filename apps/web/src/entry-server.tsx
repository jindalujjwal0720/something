import { StrictMode } from 'react';
import { renderToString } from 'react-dom/server';
import App from '@/app/app';

export async function render(url: string) {
  const { StaticRouter } = await import('react-router-dom/server');
  const html = renderToString(
    <StrictMode>
      <StaticRouter location={url}>
        <App />
      </StaticRouter>
    </StrictMode>,
  );

  return { html, head: '' };
}
