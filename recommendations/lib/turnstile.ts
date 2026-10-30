// lib/turnstile.ts: Cloudflare Turnstile server-side check
export async function verifyTurnstile(token: string, ip: string) {
  const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST',
    body: new URLSearchParams({ secret: process.env.TURNSTILE_SECRET_KEY!, response: token, remoteip: ip }),
  });
  return res.ok && (await res.json()).success === true;
}
