---
name: race-condition
description: "Races and TOCTOU: check-then-act on shared state without a transaction, lock or idempotency key."
allowed_tools: [read_file, search_code, auth_context, resource_matrix, data_access_sites]
categories: [RACE_CONDITION, BUSINESS_LOGIC]
---
# Race conditions and TOCTOU

1. Find the check-then-act shapes on state that has value: read a balance, stock, quota, coupon
   use count, invitation or token, then decide, then write. Search for the read and the write of
   the same field in one handler.
2. Decide what protects the pair: a database transaction with the right isolation (`SERIALIZABLE`
   or `SELECT ... FOR UPDATE`), an atomic conditional update (`UPDATE ... WHERE balance >= ?`,
   `findOneAndUpdate` with the condition in the filter), a unique constraint, a lock, or an
   idempotency key on the request. The absence of all of these, with the check in application
   code and the write later, is the finding.
3. Ask what two concurrent requests achieve: double spend, double refund, a coupon used twice, a
   single-use token used twice, a quota exceeded, a duplicate account. Name the concrete gain in
   `capabilitiesGained`.
4. Check the single-use artifacts separately: password-reset and invitation tokens must be consumed
   atomically (delete or mark used in the same statement that validates them).
5. This class is `live_only` in evals: static reading establishes the missing guard; the oracle is
   two concurrent requests. Keep `proofObligations` honest ("the ORM may wrap this in a
   transaction via middleware") and let the validator close them.
6. Severity: money or entitlements HIGH; duplicate records with no gain LOW.
