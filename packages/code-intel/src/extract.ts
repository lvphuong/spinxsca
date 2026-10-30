import { extractJava } from './extractors/java';
import { extractJavaScript } from './extractors/javascript';
import { extractPython } from './extractors/python';
import { getParser, languageOfPath } from './parser';
import type { FileExtraction } from './types';

const MAX_PARSE_BYTES = 1_500_000;

/** Parses one file and extracts its facts. Never throws: failures are recorded on the extraction. */
export async function extractFile(path: string, text: string): Promise<FileExtraction | undefined> {
  const language = languageOfPath(path);
  if (!language) return undefined;
  const base = {
    path,
    language,
    symbols: [],
    imports: [],
    calls: [],
    endpoints: [],
    globalControls: [],
    mounts: [],
  } satisfies FileExtraction;
  if (text.length > MAX_PARSE_BYTES) return { ...base, error: 'file too large to parse' };
  try {
    const parser = await getParser(language);
    const tree = parser.parse(text);
    if (!tree) return { ...base, error: 'parse failed' };
    try {
      const root = tree.rootNode;
      const extraction =
        language === 'python'
          ? extractPython(path, language, root)
          : language === 'java'
            ? extractJava(path, language, root)
            : extractJavaScript(path, language, root);
      if (root.hasError) extraction.error = 'file has syntax errors; extraction may be incomplete';
      return extraction;
    } finally {
      tree.delete();
      parser.delete();
    }
  } catch (err) {
    return { ...base, error: `extraction failed: ${err instanceof Error ? err.message : String(err)}` };
  }
}
