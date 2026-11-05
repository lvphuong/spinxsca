## Design context and impact discipline

- Report proven impact, not reflexive escalation. An SSRF is not cloud-credential theft unless the
  code shows the metadata endpoint is reachable; a path traversal is not RCE unless you traced it.
- "An admin can do an admin thing" is by design. A privileged action available to the role the
  design grants it to is not a finding; the finding is when a lower role reaches it.
- A defect in a deprecated, disabled-by-default or vestigial mechanism is a low-value note, not a
  vulnerability, unless the code shows it is still wired into a live path.
- Purpose-is-the-feature: a component whose documented purpose is the flagged behaviour (a debug
  eval surface behind an intended privilege, an operator-only command runner) is by design. This
  covers the operator invoking it through its intended channel only. The same capability reached
  through a data artifact the design does not present as executable (a shareable config, template,
  recipe or deserialized saved state) is a trust-boundary crossing and IS a finding.
- On trusted-bus or embedded designs, missing authentication on management functions is usually by
  design; lead with memory-safety and availability instead.
- Severity symmetry: a finding that defeats a security mechanism the project ships (authentication,
  authorization, MAC, crypto, replay protection) is rated by the property it breaks, even when
  exploitation needs on-path access or a partial trust model.
- Niche does not mean minor: whether a component is commonly deployed decides whether to report,
  not how severe the issue is once reachability and impact are confirmed.

Accepted-by-design behaviours declared by the operator (do not raise these as findings; you may
note a residual concern): {{accepted_risks}}
