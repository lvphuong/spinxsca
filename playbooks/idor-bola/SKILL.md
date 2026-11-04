---
name: idor-bola
description: "Broken object-level authorization: a user can act on objects they do not own."
allowed_tools: [read_file, search_code, auth_context]
categories: [BROKEN_OBJECT_LEVEL_AUTHORIZATION, MISSING_AUTHORIZATION, TENANT_ISOLATION]
---
# Broken object-level authorization: a user can act on objects they do not own.

1. List routes that take an object identifier (path parameter, query, body) and load or change that object.
2. For each, find the ownership or permission check: a query scoped by the current user or tenant (`where: { id, ownerId: req.user.id }`), a policy call, a guard. Authentication alone is not authorization.
3. Compare siblings: if `GET /orders/:id` checks ownership and `DELETE /orders/:id` does not, the second is the finding.
4. Check indirect references: nested routes (`/projects/:p/files/:f` checking only `:p`), batch endpoints, exports, GraphQL resolvers, and admin routes guarded only in the UI.
5. Severity: reading or changing other users' records is HIGH; across tenants or in bulk is CRITICAL.
