import env from '@/config/env';
import { createAuthClient } from 'better-auth/react';

export const authClient = createAuthClient({
  /** the base url of the server (optional if you're using the same domain) */
  baseURL: `${env.apiUrl}/v1/auth`,
});

export type Session = typeof authClient.$Infer.Session;
