# Security Reporting and Known Limits

## Report privately

Report suspected vulnerabilities through the repository's
[private vulnerability reporting form](https://github.com/Ghost-Frame/FrameShift/security/advisories/new).
Do not open a public issue or include live credentials, private keys, or tokens
in a report.

The complete repository policy is in
[SECURITY.md](https://github.com/Ghost-Frame/FrameShift/blob/main/SECURITY.md).
It covers the core FrameShift repository. Separately maintained websites and
applications use the reporting channel of their own repository.

## Current limits

FrameShift is prerelease software. The current public trust and distribution
limits are:

- Release archives are currently published for Linux x64 and Windows x64.
- Windows command-line archives are unsigned. Verify the matching entry in
  `SHA256SUMS` before extracting them.
- The separately distributed early-access Windows desktop installer is also
  unsigned and may show an unrecognized-publisher warning.
- macOS distribution is withheld until signed and notarized builds are
  available.
- Registry-installed persona packs require archive-hash and signature
  verification. Direct local-path installs may be unsigned.
- A capability manifest declares expected access but does not enforce a
  sandbox. The host agent owns tool, network, and filesystem enforcement.
- MCP draft tools cannot provide the final human review or submission intent.
- Telemetry is opt-in, but enabling it sends selection events to the configured
  endpoint. See [[Local Data and Privacy]] for the exact payload.
- A lost vault passphrase cannot be recovered by FrameShift.

These limits are not reasons to bypass a warning. Verify the artifact or use a
supported trust path.
