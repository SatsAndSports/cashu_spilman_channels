# Reporting a Vulnerability

To report security issues send an email to **tsk@thesimplekid.com**

## Automated checks

- Rust formatting, Clippy, and tests run in normal CI.
- PR dependency review fails on newly introduced high/critical vulnerabilities;
  `actionlint` validates workflow files in a separate lightweight check.
- Dependency audits run weekly, manually, and on dependency-changing PRs. PRs
  run only the affected ecosystems; changes to the audit workflow run all audits.
  Rust uses `cargo audit` against the workspace lockfile. npm audits both lockfiles
  including development dependencies. Go checks all four modules with
  `govulncheck -scan=module`, avoiding Rust/cgo builds; this reports vulnerable
  module versions, not whether vulnerable symbols are reachable. Python audits
  resolved demo requirements plus binding/kit build, runtime, and optional-extra
  requirements without building the local Rust extension. Unlocked Python
  requirements describe the current resolution, not every previously installed
  environment.
- Rust CodeQL runs weekly or manually with `build-mode: none`. It does not add a
  PR build; generated code may not be covered. Review initial results and runtime
  before expanding its triggers or languages. After merging the workflow, run
  `gh workflow run codeql.yml` to perform the first analysis.
- Dependabot covers Cargo, GitHub Actions, npm, pip, and Go modules with weekly
  grouped compatible updates and small open-PR limits. Major package upgrades
  remain separate for review.

GitHub repository settings also enable Dependabot vulnerability alerts/security
updates, secret scanning, and secret push protection. These settings are managed
on GitHub rather than by workflow YAML. Existing dependency findings can fail the
full audits even when PR dependency review passes; fixes should be reviewed as
dependency updates rather than suppressed in the workflow.
