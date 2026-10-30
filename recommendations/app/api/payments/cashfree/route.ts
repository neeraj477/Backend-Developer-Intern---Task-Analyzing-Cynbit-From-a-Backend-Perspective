// app/api/payments/cashfree/route.ts: the only code that marks an order paid
import { cashfree } from '@/lib/cashfree';
import { db } from '@/lib/db';
import { provisionAccount } from '@/lib/accounts';

export async function POST(req: Request) {
  const rawBody = await req.text(); // Cashfree signs the raw bytes, not parsed JSON
  try {
    cashfree.PGVerifyWebhookSignature(
      req.headers.get('x-webhook-signature') ?? '',
      rawBody,
      req.headers.get('x-webhook-timestamp') ?? '',
    ); // throws on mismatch
  } catch {
    return new Response('invalid signature', { status: 401 });
  }

  const event = JSON.parse(rawBody);
  if (event.type !== 'PAYMENT_SUCCESS_WEBHOOK') return new Response('ignored');

  const { order_id, order_amount } = event.data.order;
  // Atomic and idempotent: only the first matching delivery flips PENDING to PAID
  const { count } = await db.order.updateMany({
    where: { id: order_id, status: 'PENDING', amount: order_amount },
    data: { status: 'PAID', paidAt: new Date() },
  });
  if (count === 1) await provisionAccount(order_id);
  return new Response('ok');
}
