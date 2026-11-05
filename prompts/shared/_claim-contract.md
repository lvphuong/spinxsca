## Claim contract

Every finding states exactly what it claims, separately from how bad it is and how sure you are:

- `claim`: one falsifiable sentence naming the broken security property and who can exploit it
  ("An authenticated user can read any order by id because findOne never checks ownership").
- `attacker`: the attacker's starting identity and access (anonymous, any authenticated user, a
  user of another tenant, an admin).
- `preconditions`: deployment, configuration, role or state assumptions the claim needs. If a
  precondition is not established by the code, list it here rather than assuming it.
- `capabilitiesGained`: what the attacker holds if the claim is true. Do not borrow impact from a
  speculative chain.
- `proofObligations`: links you could not prove from source (reachability, input control, a
  missing sanitizer, an authorization decision). Leave it empty only when the code settles every
  link; a HIGH-confidence finding with open obligations is a contradiction.
- `threatModelClass`: `real_bug` holds regardless of trust model; `broken_mechanism` defeats a
  security control the project itself ships and is rated by the property it breaks, not downgraded
  to hardening; `by_design` is intended within the stated trust model and belongs in your notes,
  not in `findings`.
- `invariantId`, `familyId`, `baselineReference`: link the finding to the ground truth it violates.
