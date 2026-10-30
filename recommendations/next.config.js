// next.config.js
const csp = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' https://www.googletagmanager.com https://sdk.cashfree.com",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com",
  "img-src 'self' data: blob: https://*.google-analytics.com https://*.googletagmanager.com",
  "connect-src 'self' https://*.google-analytics.com https://*.analytics.google.com https://*.cashfree.com",
  "frame-src https://*.cashfree.com",
  "frame-ancestors 'none'",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self' https://*.cashfree.com",
  'upgrade-insecure-requests',
  'report-uri /api/csp-report', // a route handler that logs violation reports
].join('; ');

const securityHeaders = [
  { key: 'Content-Security-Policy-Report-Only', value: csp }, // rename to Content-Security-Policy after a clean week
  { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
];

module.exports = {
  poweredByHeader: false,
  experimental: { serverActions: { bodySizeLimit: '256kb' } }, // forms are small; the default is 1 MB
  async headers() {
    return [{ source: '/:path*', headers: securityHeaders }];
  },
};
