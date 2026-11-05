---
name: workflow-state-bypass
description: "Workflow and state-machine bypass: a transition reachable out of order or without its precondition."
allowed_tools: [read_file, search_code, auth_context, resource_matrix, data_access_sites]
categories: [BUSINESS_LOGIC]
---
# Workflow and state-machine bypass

1. Reconstruct the state machine from the code: the status enum or constants, the handlers that
   move an object between states (pay, approve, ship, cancel, refund, publish, verify), and the
   intended order. Write it down before hunting.
2. For each transition handler, find the precondition check on the current state (`if (order.status
   !== 'PAID') throw`, a state-machine library guard, a database condition). A transition without
   the check, or with the check on a client-supplied copy of the state, is the finding.
3. Look for the side doors: a generic update endpoint that accepts `status` directly (see
   mass-assignment), an admin or support tool, an import, a webhook that trusts its payload, a
   retry or job that replays a step.
4. Multi-step flows with a client-held token or step id: verify the server checks the previous
   steps completed (payment confirmed before fulfilment, email verified before role granted, both
   approvers before release).
5. Severity: skipping payment, approval or verification is HIGH or CRITICAL; reordering harmless
   steps is LOW. `live_only` in evals: the oracle is calling the later step first.
