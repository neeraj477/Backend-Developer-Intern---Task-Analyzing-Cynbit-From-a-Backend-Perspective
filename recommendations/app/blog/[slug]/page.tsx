// app/blog/[slug]/page.tsx (same pattern for case studies, careers and diaries)
import { unstable_cache } from 'next/cache';
import { db } from '@/lib/db';

export const revalidate = 3600;     // served from the edge, refreshed at most hourly
export const dynamicParams = true;  // a new slug renders once, then caches

const getPost = unstable_cache(
  async (slug: string) => db.post.findFirst({ where: { slug, published: true } }),
  ['post'],
  { tags: ['posts'] },
);

export async function generateStaticParams() {
  const posts = await db.post.findMany({ where: { published: true }, select: { slug: true } });
  return posts.map(({ slug }) => ({ slug }));
}
