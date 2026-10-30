// app/careers/actions.ts: stricter schema, less personal data
'use server';
import { z } from 'zod';
import { publicAction } from '@/lib/action';
import { db } from '@/lib/db';
import { enqueue } from '@/lib/queue';

const optionalHttpsUrl = z.preprocess(
  (v) => (v === '' ? undefined : v),
  z.string().trim().url().max(300)
    .refine((u) => new URL(u).protocol === 'https:', 'Use an https:// link') // blocks javascript: URLs
    .optional(),
);

export const submitCandidateApplication = publicAction(
  'apply',
  z.object({
    fullName: z.string().trim().min(2).max(100),
    email: z.string().trim().toLowerCase().email().max(254),
    phone: z.string().trim().regex(/^\+?[0-9 ]{10,15}$/),
    skills: z.string().trim().max(500),
    linkedinUrl: optionalHttpsUrl,
    portfolioUrl: optionalHttpsUrl,
    professionalProfileUrl: optionalHttpsUrl,
    message: z.string().trim().max(3000).optional(),
    agreedToTerms: z.literal('on'),
    // dob, gender, permanentAddress: removed until a hiring step needs them
  }),
  async (input) => {
    const { id } = await db.application.create({ data: input }); // encrypted at rest, fixed retention
    await enqueue('notify-recruiters', { applicationId: id });   // the email carries an ID, not the data
    return { applicationId: id };
  },
);
