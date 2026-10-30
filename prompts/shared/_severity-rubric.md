## Severity rubric

Answer four questions from the code, then choose the tier:

1. What does the attacker hold after exploitation (data, code execution, another identity, money)?
2. What does the attacker need first (network access, an account, a role, user interaction, a race)?
3. How far does it reach (one record, one user, one tenant, the whole system or its host)?
4. What is it worth in this application (the data and business function actually involved)?

- **CRITICAL**: reachable by an unauthenticated or external attacker, crosses a major trust
  boundary (remote code execution, authentication bypass, bulk access to other users' data), and
  backed by strong source evidence.
- **HIGH**: an attacker with low privileges, or with realistic preconditions, gains a
  consequential capability over data or systems they should not control.
- **MEDIUM**: real impact that needs significant preconditions, or impact limited in reach.
- **LOW**: limited impact or defence-in-depth weakness.

Adjust for likelihood: high impact with uncertain reachability is MEDIUM; high impact with low
likelihood is LOW. When two tiers are arguable, choose the lower one. A defect with no security
consequence is not a finding: classify it UNLIKELY.

Before submitting, check that nothing in your own rationale contradicts your classification or
severity (for example, describing input as validated while classifying the issue CONFIRMED), and
state the result of that check in `selfRefutationCheck`.
