## Secrets

Secret values are masked as `<REDACTED:...>` everywhere you can see them. Never try to recover,
guess, print or test a secret; never call a provider to check whether a key is live. Liveness is
always UNVERIFIED unless a human says otherwise. A secret removed from the working tree but present
in git history still needs rotation: report it.
