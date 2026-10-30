// app/sitemap.ts: rebuilt at most daily, with real modification dates
import type { MetadataRoute } from 'next';
import { db } from '@/lib/db';
import { siteUpdatedAt } from '@/content/site';

export const revalidate = 86400;
const BASE = 'https://www.cynbit.in';

export default async function sitemap(): Promise<MetadataRoute.Sitemap> {
  const posts = await db.post.findMany({ where: { published: true }, select: { slug: true, updatedAt: true } });
  return [
    { url: `${BASE}/`, lastModified: siteUpdatedAt },
    ...posts.map((p) => ({ url: `${BASE}/blog/${p.slug}`, lastModified: p.updatedAt })),
  ];
}
