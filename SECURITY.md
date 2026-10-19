# Security

## Reporting a vulnerability

Please report security problems privately, through GitHub's private vulnerability
reporting on this repository ("Security" tab, "Report a vulnerability"), not in a public
issue. Include what you ran, what you expected and what happened. You should get a reply
within a week.

## What counts

This tool reads untrusted inputs by design: third-party application checkouts, package
tarballs, Go module zips and crates, advisory text, and model output. Reports we
especially want:

- anything in a checkout, package or advisory that gets code executed on the machine
  running the tool, or files written outside its caches;
- a way past the package integrity checks, the archive extraction checks, or the
  govulncheck / Jelly sandboxes;
- app source reaching a destination its `--egress` mode forbids;
- a crafted package or app that makes a tier settle `not_reachable` for code that is in
  fact reachable (prompt injection that flips a verdict included). A wrong
  `not_reachable` hides a risk, so we treat it as a security bug.

Out of scope: a model simply being wrong on an ordinary case (that's a calibration
issue: open a normal issue with the case), and vulnerabilities in the deliberately
vulnerable apps the cases point at.
