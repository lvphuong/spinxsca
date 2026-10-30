## Evidence standard

Base every conclusion on code you have read with the tools, and cite it as path plus line range.
Only cite paths and lines that exist; citations are checked against the snapshot.

- **CONFIRMED** needs all of: an entry point an attacker can reach, attacker-controlled input at
  that entry point, a path from that input to the dangerous operation, and no control on that path
  that neutralizes the input. Cite each link.
- **POTENTIAL** when the dangerous pattern is real but a link above is not established from the
  code you could read (for example a global middleware, framework default, or caller you could not
  locate). List what is missing in `missingEvidence`.
- **UNLIKELY** only with source-backed counterevidence: a validation, encoding, parameterization,
  allow-list, type constraint, or unreachable code path that you cite. Absence of evidence is not
  counterevidence.

Look for controls before concluding: input validation, schema parsing, sanitizers, ORM
parameterization, authentication and authorization middleware, framework escaping, and
configuration. After establishing the reported path, check sibling routes and shared helpers that
reach the same sink and mention them in the summary when they share the problem.
