import { defineConfig } from 'drizzle-kit';
import { readFileSync } from 'fs';
import path from 'path';
import { env } from './src/config';

export default defineConfig({
  out: './drizzle',
  schema: './src/db/schema',
  dialect: 'postgresql',
  dbCredentials: {
    host: env.db.host,
    port: env.db.port,
    user: env.db.user,
    password: env.db.pass,
    database: env.db.name,
    ssl: {
      rejectUnauthorized: true,
      ca: readFileSync(path.join(__dirname, './ca-pg.pem')).toString(),
    },
  },
});
