// lib/session.ts: opaque session ID; the server enforces both timeouts
import 'server-only';
import { cookies } from 'next/headers';
import { randomBytes, createHash } from 'node:crypto';
import { Redis } from '@upstash/redis';

const redis = Redis.fromEnv();
const IDLE_SECONDS = 30 * 60;          // signed out after 30 idle minutes
const ABSOLUTE_MS = 12 * 60 * 60_000;  // and after 12 hours regardless
const keyFor = (id: string) => `session:${createHash('sha256').update(id).digest('hex')}`;

export async function createSession(userId: string) {
  const id = randomBytes(32).toString('base64url');
  await redis.set(keyFor(id), { userId, createdAt: Date.now() }, { ex: IDLE_SECONDS });
  (await cookies()).set('__Host-session', id, { httpOnly: true, secure: true, sameSite: 'lax', path: '/' });
}

export async function getSession() {
  const id = (await cookies()).get('__Host-session')?.value;
  if (!id) return null;
  const session = await redis.get<{ userId: string; createdAt: number }>(keyFor(id));
  if (!session || Date.now() - session.createdAt > ABSOLUTE_MS) return null;
  await redis.expire(keyFor(id), IDLE_SECONDS); // slide the idle window
  return session;
}
