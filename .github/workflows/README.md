# GitHub Actions workflows

- **codeql.yml** – CodeQL analysis (push/PR to master, weekly).
- **make-multi-platform.yml** – Build with Make on Rocky Linux 10 (server/agent) and Windows agent (cross-compile). Based on the multi-platform CI idea from PR #2158 by @cmac9203; adapted for this project’s Make build.
