---
name: path-traversal
description: "Path traversal: input controls a filesystem path outside the intended directory."
allowed_tools: [read_file, search_code]
categories: [PATH_TRAVERSAL]
---
# Path traversal: input controls a filesystem path outside the intended directory.

1. Sinks: `fs.readFile`/`createReadStream`/`sendFile`/`res.download`, `open()`, `send_file`, `Files.read*`, archive extraction (zip slip), template loaders.
2. Trace the path component to request data (query, params, body, uploaded file names, archive entry names).
3. Controls that count: resolving the path (`path.resolve`, `os.path.realpath`) and checking it starts with the base directory plus a separator; mapping ids to files server-side; `res.sendFile(name, { root })` with dotfiles denied. Stripping `../` once, checking only the extension, or `path.join` alone do not count.
4. Consider encoded traversal (`%2e%2e%2f`), absolute paths, Windows separators and symlinks inside the base directory.
5. Impact depends on what is readable or writable: source and secrets (HIGH), arbitrary write (CRITICAL).
