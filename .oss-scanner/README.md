# Anthropic OSS Scanner support

Files in this directory enroll OSSEC HIDS with
[Anthropic’s OSS Scanner](https://red.anthropic.com/oss-scanner/):

| File | Purpose |
|------|---------|
| `Dockerfile` | Offline-audit image: deps, DEBUG server + agent builds, unit tests |
| `threat_model.md` | Scope, severity rubric, and exercise hints for the scanner |

## Enrollment (separate PR)

Core maintainers enroll by opening a PR against
[anthropics/oss-scanner](https://github.com/anthropics/oss-scanner) that adds
`projects/ossec-hids/project.yaml` (start from their `templates/project.yaml`).

Suggested `project.yaml` once this branch is on `ossec/ossec-hids` `main`
(or pin a tag/branch with `#…`):

```yaml
repo: https://github.com/ossec/ossec-hids#main
primary_contact: security@ossec.net
auto_ccs:
  - scott@atomicorp.com
homepage: https://www.ossec.net
disabled: false
dockerfile: .oss-scanner/Dockerfile
threat_model: .oss-scanner/threat_model.md
```

Before submitting that PR:

1. Merge this `.oss-scanner/` support into the scanned branch.
2. Locally clone `anthropics/oss-scanner`, add the yaml above, then run
   `tools/validate.py` and `tools/check ossec-hids` (needs Docker + PyYAML).

## Local smoke-test of the Dockerfile

From the OSSEC repo root:

```bash
docker build -f .oss-scanner/Dockerfile -t ossec-oss-scanner .
docker run --rm --network=none -it ossec-oss-scanner bash
# inside: ls src/ossec-analysisd .oss-scanner/bin/server .oss-scanner/bin/agent
```
