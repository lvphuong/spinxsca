import { createReadStream, createWriteStream } from 'node:fs';
import { Unzip, UnzipInflate, Zip, ZipDeflate } from 'fflate';

/** Streams the entries of a (possibly very large) zip file without loading it into memory. */
export async function forEachZipEntry(path: string, onEntry: (name: string, data: Uint8Array) => void): Promise<void> {
  let failure: unknown;
  const unzip = new Unzip((file) => {
    if (file.name.endsWith('/')) return;
    const chunks: Uint8Array[] = [];
    file.ondata = (err, data, final) => {
      if (err) {
        failure = err;
        return;
      }
      chunks.push(data);
      if (final) onEntry(file.name, concat(chunks));
    };
    file.start();
  });
  unzip.register(UnzipInflate);
  for await (const chunk of createReadStream(path, { highWaterMark: 1 << 20 })) {
    unzip.push(chunk as Uint8Array);
    if (failure) throw failure;
  }
  unzip.push(new Uint8Array(0), true);
  if (failure) throw failure;
}

/** Writes a zip archive entry by entry (deflate level 1: materialized databases favour speed). */
export async function writeZip(path: string, entries: Iterable<{ name: string; data: Uint8Array }>): Promise<number> {
  const out = createWriteStream(path);
  let count = 0;
  const done = new Promise<void>((resolve, reject) => {
    out.on('finish', () => resolve());
    out.on('error', reject);
  });
  const zip = new Zip((err, chunk, final) => {
    if (err) {
      out.destroy(err);
      return;
    }
    out.write(chunk);
    if (final) out.end();
  });
  for (const entry of entries) {
    const file = new ZipDeflate(entry.name, { level: 1 });
    zip.add(file);
    file.push(entry.data, true);
    count++;
  }
  zip.end();
  await done;
  return count;
}

function concat(chunks: Uint8Array[]): Uint8Array {
  if (chunks.length === 1) return chunks[0] as Uint8Array;
  const total = chunks.reduce((n, c) => n + c.byteLength, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.byteLength;
  }
  return out;
}
