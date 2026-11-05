# Logic and authorization evaluation suite (Phase 6)

Cases whose bugs no pattern rule can see: a sibling operation without the ownership scope its
siblings have, tenant isolation, a check-then-act race, mass assignment, a workflow step reachable
out of order, a fail-open authentication middleware, and negative controls (the control exists; an
admin does an admin thing). Ground truth is `detectable_by: [ai]`, so it counts only when the suite
runs with `--ai standard` or `--ai deep` (ADR-049); below that every case is pending.

Run in CI without a model:

```
pnpm spinxsca eval --suite logic --ai standard --ai-provider scripted
```

The scripted provider derives recon and findings from the deterministic census worksheet (resource ×
operation matrix, data-access scope), so it detects the sibling-without-scope shape (101, 104, 109)
and stays silent on the negatives (102, 103). Cases marked `live_only` (105–108) need a real model
and are reported as pending under the scripted provider:

```
pnpm spinxsca eval --suite logic --ai standard --ai-provider anthropic
```

| Case | Shape | Scripted |
|---|---|---|
| 101 IDOR sibling (Express + Sequelize) | `PUT /orders/:id` updates by id alone; `GET /orders/:id` is the baseline | detected |
| 102 control exists (NestJS) | every operation carries `OwnershipGuard` or a scoped query | negative |
| 103 admin by design (Express) | `/admin/users/:id/role` behind `requireRole('admin')`; operator context declares the role | negative |
| 104 tenant isolation (Express + Prisma) | `GET /projects/:id` without the tenant predicate its siblings use | detected |
| 105 refund race (Express) | balance check then write without a transaction | live only |
| 106 mass assignment (NestJS) | request body spread into the user update, `role` reachable | live only |
| 107 workflow bypass (Flask) | `ship` never checks `PAID` | live only |
| 108 fail-open auth (Express) | token verification failure falls through to `next()` | live only |
| 109 correct sibling baseline (Spring) | three methods carry `@PreAuthorize`, `close` does not | detected |

Metrics beyond precision and recall: **sibling-sweep recall** (fraction of variant families whose every
member was reported; members share a `family` in `case.yaml`) and **invariant coverage** (fraction of
recon invariants that received a PASS/FAIL/UNKNOWN result). Thresholds are in `thresholds.yaml`.
