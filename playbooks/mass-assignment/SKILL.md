---
name: mass-assignment
description: "Mass assignment: request fields bound to a model so a client sets role, owner, price or status."
allowed_tools: [read_file, search_code, auth_context, resource_matrix, data_access_sites]
categories: [BUSINESS_LOGIC, MISSING_AUTHORIZATION]
---
# Mass assignment

1. Find the binding sites: `Object.assign(entity, req.body)`, spread of the body into a create or
   update (`{ ...req.body }`, `prisma.user.update({ data: req.body })`), `**kwargs`, `Model(**data)`,
   `@Body()` DTOs without a whitelist, Spring `@ModelAttribute`, serializers with `fields = '__all__'`.
2. List the sensitive fields of the model the binding touches: role, isAdmin, permissions, ownerId,
   tenantId, status, price, balance, verified, email of a verified account. A binding that can set
   any of them from the client is the finding; cite the model field and the binding line.
3. Check for a real whitelist between the request and the model: a DTO with only the allowed
   properties and `whitelist: true`/`forbidNonWhitelisted`, `pick`/`only`, a serializer with an
   explicit `fields` list, `strong_parameters`. Validation of types alone does not restrict fields.
4. Compare siblings: a create path that whitelists next to an update path that spreads the body is
   the variant finding.
5. Severity: role, permission, owner or tenant fields are HIGH or CRITICAL; cosmetic fields are
   LOW. `live_only` in evals: the oracle is a request that sets the field.
