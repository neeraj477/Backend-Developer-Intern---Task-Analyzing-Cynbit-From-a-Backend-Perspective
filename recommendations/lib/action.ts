// lib/action.ts
import 'server-only';
import { z } from 'zod';
import { headers } from 'next/headers';
import { Ratelimit } from '@upstash/ratelimit';
import { Redis } from '@upstash/redis';
import { verifyTurnstile } from '@/lib/turnstile';
import { log } from '@/lib/log';

type ErrorCode = 'INVALID_INPUT' | 'RATE_LIMITED' | 'BOT_CHECK_FAILED' | 'INTERNAL';
export type ActionResult<T> =
  | { ok: true; data: T }
  | { ok: false; code: ErrorCode; requestId: string; fieldErrors?: Record<string, string[] | undefined> };

const limiter = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(5, '10 m'),
  prefix: 'action',
});

export function publicAction<S extends z.ZodTypeAny, T>(
  name: string,
  schema: S,
  run: (input: z.infer<S>) => Promise<T>,
) {
  return async (form: FormData): Promise<ActionResult<T | null>> => {
    const h = await headers();
    const requestId = h.get('x-vercel-id') ?? crypto.randomUUID();
    const ip = h.get('x-real-ip') ?? 'unknown';

    if (form.get('website')) return { ok: true, data: null }; // honeypot filled: drop silently
    const parsed = schema.safeParse(Object.fromEntries(form));
    if (!parsed.success)
      return { ok: false, code: 'INVALID_INPUT', requestId, fieldErrors: parsed.error.flatten().fieldErrors };
    if (!(await limiter.limit(`${name}:${ip}`)).success) return { ok: false, code: 'RATE_LIMITED', requestId };
    if (!(await verifyTurnstile(String(form.get('cf-turnstile-response') ?? ''), ip)))
      return { ok: false, code: 'BOT_CHECK_FAILED', requestId };

    try {
      return { ok: true, data: await run(parsed.data) };
    } catch (err) {
      log.error({ action: name, requestId, err }); // no form contents in logs
      return { ok: false, code: 'INTERNAL', requestId };
    }
  };
}
