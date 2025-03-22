import { StrictMode } from 'react';
import { hydrateRoot } from 'react-dom/client';
import App from '@/app/app';
import './index.css';
import { BrowserRouter } from 'react-router-dom';

hydrateRoot(
  document.getElementById('root')!,
  <StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </StrictMode>,
);
