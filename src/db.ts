import { drizzle } from 'drizzle-orm/node-postgres';
import { Pool } from 'pg';
import { config } from './config';
import * as schema from './schema';

const pool = new Pool({
  connectionString: config.databaseUrl,
  ssl: { rejectUnauthorized: false }, // Required for Neon with sslmode=require
});

export const db = drizzle(pool, { schema });

// Database query functions
export async function findUserByEmail(email: string) {
  return db.query.users.findFirst({
    where: (users, { eq }) => eq(users.email, email),
  });
}

export async function findUserById(id: number) {
  return db.query.users.findFirst({
    where: (users, { eq }) => eq(users.id, id),
  });
}

export async function insertRefreshToken(userId: number, token: string, expiresAt: Date) {
  await db.insert(schema.refreshTokens).values({ userId, token, expiresAt });
}

export async function findRefreshToken(token: string) {
  return db.query.refreshTokens.findFirst({
    where: (tokens, { eq }) => eq(tokens.token, token),
  });
}

export async function deleteRefreshToken(token: string) {
  await db.delete(schema.refreshTokens).where((tokens, { eq }) => eq(tokens.token, token));
}