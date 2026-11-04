import { z } from 'zod';

export const FixReviewDeliverable = z.strictObject({
  verdict: z.enum(['approve', 'request_changes', 'reject']),
  comments: z.string().min(10).max(3000).describe('What is right or wrong with the fix, with file:line references'),
  risks: z.array(z.string().max(400)).max(8).describe('Behaviour the fix may break or variants it does not cover'),
});
export type FixReviewDeliverable = z.infer<typeof FixReviewDeliverable>;

export interface RemediationTarget {
  findingId: string;
  title: string;
  severity: string;
  location: string;
}

export interface RemediationOutcome {
  findingId: string;
  patchId?: string;
  status: 'applied' | 'awaiting_approval' | 'declined' | 'rejected' | 'unverified';
  reason: string;
  approvalId?: string;
}

export function fixReviewPrompt(
  t: RemediationTarget,
  patch: { diff?: string; summary?: string; verification: unknown; reason?: string },
): string {
  return [
    `Finding ${t.findingId}: ${t.title} (${t.severity}) at ${t.location}.`,
    `Fix summary (by another agent): ${patch.summary ?? '(none)'}`,
    `Host verification: ${patch.reason ?? ''}\n${JSON.stringify(patch.verification, null, 2)}`,
    `<untrusted_patch>\n${(patch.diff ?? '').slice(0, 20_000)}\n</untrusted_patch>`,
    'Check that the change closes the reported path and its variants, keeps legitimate behaviour, does not weaken tests or checks and touches nothing unrelated. Read the surrounding code before deciding. Then call `submit_fix_review`.',
  ].join('\n\n');
}
