// app/portal/actions.ts
'use server';
import 'server-only';
import { z } from 'zod';
import { headers } from 'next/headers';
import argon2 from 'argon2';
import { Ratelimit } from '@upstash/ratelimit';
import { Redis } from '@upstash/redis';
import { verifyTurnstile } from '@/lib/turnstile';
import { createSession } from '@/lib/session';
import { db } from '@/lib/db';

const redis = Redis.fromEnv();
const perIp = new Ratelimit({ redis, limiter: Ratelimit.slidingWindow(10, '15 m'), prefix: 'login:ip' });
const perAccount = new Ratelimit({ redis, limiter: Ratelimit.slidingWindow(5, '15 m'), prefix: 'login:acct' });
const DUMMY_HASH = process.env.DUMMY_ARGON2_HASH!; // hash of a random string: unknown emails take as long

const Login = z.object({
  email: z.string().trim().toLowerCase().email().max(254),
  password: z.string().min(12).max(128),
  'cf-turnstile-response': z.string().min(1),
});

export async function loginToPortal(form: FormData) {
  const input = Login.safeParse(Object.fromEntries(form));
  if (!input.success) return { ok: false, code: 'INVALID_CREDENTIALS' } as const;

  const ip = (await headers()).get('x-real-ip') ?? 'unknown';
  const [byIp, byAccount] = await Promise.all([perIp.limit(ip), perAccount.limit(input.data.email)]);
  if (!byIp.success || !byAccount.success) return { ok: false, code: 'RATE_LIMITED' } as const;
  if (!(await verifyTurnstile(input.data['cf-turnstile-response'], ip)))
    return { ok: false, code: 'BOT_CHECK_FAILED' } as const;

  const user = await db.user.findUnique({ where: { email: input.data.email } });
  const valid = await argon2.verify(user?.passwordHash ?? DUMMY_HASH, input.data.password);
  if (!user || !valid) return { ok: false, code: 'INVALID_CREDENTIALS' } as const;

  await createSession(user.id); // a new random session ID on every login
  return { ok: true } as const;
}
