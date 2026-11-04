---
name: sqli
description: "SQL injection: confirm a query built from input reaches the database without parameterization."
allowed_tools: [read_file, search_code]
categories: [SQL_INJECTION, NOSQL_INJECTION]
---
# SQL injection: confirm a query built from input reaches the database without parameterization.

1. Identify the query API at the sink (raw driver `query`/`execute`, ORM `raw`/`literal`, query builders with `whereRaw`, template strings, `%`/`format`/f-strings in Python, `Statement` vs `PreparedStatement` in Java).
2. Separate values from structure: values bound through placeholders (`?`, `$1`, `:name`, `%s` passed as params) are safe; anything concatenated or interpolated into the SQL text is not, including identifiers and `ORDER BY`/`LIMIT` fragments.
3. Trace the interpolated value back to a request field, header, cookie, path parameter or stored user data (second order).
4. Controls that count: parameterization, strict allow-lists for identifiers, numeric parsing that rejects non-numbers, ORM methods that escape. Controls that do not: blacklist filtering, `escape` of quotes only, client-side validation, length limits.
5. NoSQL: user-controlled objects in Mongo filters (`$where`, `$ne`, `$gt` from JSON bodies) are injection; casting to string or schema validation neutralizes them.
6. Severity follows the data the connection can reach and whether the route is unauthenticated.
