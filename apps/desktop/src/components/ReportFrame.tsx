/** Content Security Policy injected into every report: no network, no frames, inline styles only. */
export const REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:";

export function isolatedDocument(html: string): string {
  const meta = `<meta http-equiv="Content-Security-Policy" content="${REPORT_CSP}">`;
  return /<head[^>]*>/i.test(html) ? html.replace(/<head[^>]*>/i, (m) => `${m}${meta}`) : `<!doctype html><html><head>${meta}</head><body>${html}</body></html>`;
}

/**
 * Reports are untrusted documents: rendered in a sandboxed iframe without same-origin, scripts or
 * forms, under a CSP that blocks every network request.
 */
export function ReportFrame({ html, title }: { html: string; title: string }) {
  return <iframe className="report" title={title} sandbox="" referrerPolicy="no-referrer" srcDoc={isolatedDocument(html)} />;
}
