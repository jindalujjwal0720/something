import { drizzle } from 'drizzle-orm/node-postgres';
import { Pool } from 'pg';
import { readFileSync } from 'fs';
import path from 'path';
import { env } from '../config';

export const pool = new Pool({
  host: env.db.host,
  port: env.db.port,
  user: env.db.user,
  password: env.db.pass,
  database: env.db.name,
  ssl: env.db.sslEnabled
    ? {
        rejectUnauthorized: true,
        ca: readFileSync(path.join(__dirname, './../../ca-pg.pem')).toString(),
      }
    : false,
});

export const db = drizzle({ client: pool });
