/**
 * Candidate drafts reported by an AI role carry a scanner id of `ai` (standard investigation) or an
 * `ai-` prefix (`ai-review` for the autonomous case). They group with scanner output by category
 * family and never become the primary candidate when a deterministic scanner reported the same
 * issue (ADR-024, ADR-050).
 */
export function isAiScanner(scanner: string): boolean {
  return scanner === 'ai' || scanner.startsWith('ai-');
}
