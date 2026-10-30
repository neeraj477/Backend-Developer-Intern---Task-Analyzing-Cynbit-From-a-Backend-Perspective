// app/bitelevate/actions.ts
'use server';
import 'server-only';
import { z } from 'zod';
import { cookies } from 'next/headers';
import { randomUUID } from 'node:crypto';
import { db } from '@/lib/db';
import { priceFor, TRACKS, DURATIONS } from '@/lib/catalogue'; // prices live only on the server
import { createCashfreeOrder } from '@/lib/cashfree';        // wraps Cashfree's create-order API

const OrderInput = z.object({
  fullName: z.string().trim().min(2).max(100),
  email: z.string().trim().toLowerCase().email().max(254),
  phone: z.string().trim().regex(/^\+?[0-9 ]{10,15}$/),
  university: z.string().trim().min(2).max(120),
  track: z.enum(TRACKS),          // unknown tracks are rejected, not priced
  duration: z.enum(DURATIONS),
  referralName: z.string().trim().max(100).optional(),
  ambitions: z.string().trim().max(2000),
});

export async function createOrder(form: FormData) {
  const input = OrderInput.safeParse(Object.fromEntries(form));
  if (!input.success) return { ok: false, code: 'INVALID_INPUT' } as const;

  const amount = priceFor(input.data.track, input.data.duration); // never read from the request
  const orderId = `be_${randomUUID()}`;
  await db.order.create({ data: { id: orderId, ...input.data, amount, status: 'PENDING' } });

  const session = await createCashfreeOrder({
    orderId,
    amount,
    customer: { id: orderId, email: input.data.email, phone: input.data.phone },
    returnUrl: 'https://www.cynbit.in/bitelevate/status', // carries no secret
  });

  (await cookies()).set('__Host-be-order', orderId, {
    httpOnly: true, secure: true, sameSite: 'lax', path: '/', maxAge: 60 * 60,
  });
  return { ok: true, paymentSessionId: session.paymentSessionId } as const;
}

export async function getOrderStatus() {
  const orderId = (await cookies()).get('__Host-be-order')?.value;
  if (!orderId) return { status: 'UNKNOWN' } as const;
  const order = await db.order.findUnique({ where: { id: orderId }, select: { status: true } });
  return { status: order?.status ?? 'UNKNOWN' } as const; // status only, never credentials
}
