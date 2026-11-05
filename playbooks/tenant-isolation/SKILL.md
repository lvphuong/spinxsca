---
name: tenant-isolation
description: "Tenant isolation: data of one tenant reachable from another tenant's session."
allowed_tools: [read_file, search_code, auth_context, resource_matrix, data_access_sites]
categories: [TENANT_ISOLATION, BROKEN_OBJECT_LEVEL_AUTHORIZATION]
---
# Tenant isolation

1. Establish how the current tenant is derived (token claim, subdomain, header, path segment, a
   row looked up from the user) and where that derivation lives. A tenant id taken from the request
   body or query, or from a header the client controls, is itself a finding.
2. Find every data access on tenant-owned tables (`data_access_sites`): each query, update, delete
   and aggregate must filter by the tenant (`where: { tenantId }`, a schema per tenant, a scoped
   repository, row-level security). The baseline-correct reference is one query that does it right.
3. Compare siblings: the lookup by primary key alone (`findUnique({ where: { id } })`) next to a
   sibling that also filters by tenant is the finding. Joins and nested relations that re-fetch
   related rows without the filter count too.
4. Check the indirect paths: exports, reports, search indexes, background jobs, caches keyed
   without the tenant, file storage paths, websocket rooms, admin endpoints.
5. Check the write side: creating or updating a row with a tenant id from the request, moving an
   object between tenants, inviting a user into another tenant.
6. Severity: reading another tenant's data is HIGH; writing it, or enumerating it in bulk, is
   CRITICAL. Report each unscoped operation separately with the tenant id derivation as evidence.
