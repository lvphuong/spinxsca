---
name: business-logic
description: "Business-logic flaws: a rule the application is supposed to enforce holds in one path and not another."
allowed_tools: [read_file, search_code, auth_context, resource_matrix, data_access_sites]
categories: [BUSINESS_LOGIC, MISSING_AUTHORIZATION, BROKEN_OBJECT_LEVEL_AUTHORIZATION]
---
# Business-logic flaws

Work invariant-first: the bug is a rule that is not enforced, not a pattern that matches.

1. Write down the rule before reading for the bug: who may do what, to which object, in which
   state, within which limits (quantity, amount, rate, time window). The ground truth's invariants
   and the operator's business invariants are the starting list; add rules the code itself implies
   (a `status` enum, a `maxQuantity` constant, a `price` taken from the catalogue).
2. For each rule, find every path that must enforce it: the main handler, batch and bulk variants,
   import/export, admin tools, webhooks, scheduled jobs, GraphQL resolvers, retries. Use
   `resource_matrix` and `search_code` for the same verb or field name.
3. Compare the paths against the baseline-correct reference: the path that lacks the check, uses a
   client-supplied value where the others compute it (price, total, discount, role, owner), or
   skips a state precondition is the finding.
4. Client-controlled values that should be server-derived are findings even when "validated": a
   positive integer `price` is still the attacker's price.
5. Negative and boundary values: quantity 0 or negative, amounts above a limit, a coupon applied
   twice, a transfer to oneself, an operation on an archived or deleted object.
6. Severity follows the rule broken: money, entitlements and cross-user data are HIGH or
   CRITICAL; cosmetic or self-inflicted inconsistencies are LOW. An admin-only path that an admin
   misuses is by design.
