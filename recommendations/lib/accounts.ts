// lib/accounts.ts: no password ever leaves the server
import 'server-only';
import { randomBytes, createHash } from 'node:crypto';
import { db } from '@/lib/db';
import { sendSetPasswordEmail } from '@/lib/email'; // Resend

export async function provisionAccount(orderId: string) {
  const order = await db.order.findUniqueOrThrow({ where: { id: orderId } });
  const user = await db.user.upsert({
    where: { email: order.email },
    create: { email: order.email, passwordHash: null },
    update: {},
  });
  const token = randomBytes(32).toString('base64url');
  await db.passwordSetup.create({
    data: {
      userId: user.id,
      tokenHash: createHash('sha256').update(token).digest('hex'), // store only the hash
      expiresAt: new Date(Date.now() + 30 * 60_000),                // 30 minutes, single use
    },
  });
  await sendSetPasswordEmail(order.email, `https://portal.cynbit.in/set-password#${token}`);
}
