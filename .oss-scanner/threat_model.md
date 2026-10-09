# OSSEC HIDS threat model (Anthropic OSS Scanner)

## What this project does and where untrusted input enters

OSSEC HIDS is a host-based intrusion detection system: a manager (`ossec-analysisd`,
`ossec-remoted`, `ossec-authd`, `ossec-maild`, `ossec-dbd`, `ossec-csyslogd`,
`ossec-execd`) plus Unix/Windows agents (`ossec-agentd`, `ossec-logcollector`,
`ossec-syscheckd`, `agent-auth`).

Treat as attacker-controlled:

- Agent ↔ manager protocol traffic on the remoted/authd ports (UDP/TCP and TLS
  for authd), including malformed frames, oversized payloads, replayed or
  forged agent messages, and registration requests.
- Log lines and Windows event payloads ingested by logcollector / analysisd
  decoders and rules (syslog, JSON, multiline, eventchannel, command output).
- File and registry contents observed by FIM/syscheck and rootcheck, including
  adversarial filenames, symlinks, ACL/security descriptors, and truncated or
  locked files during realtime watches.
- Local configuration and shared agent config (`ossec.conf`, `agent.conf`,
  decoders, rules, CDB lists, rootcheck policies) when an attacker can write
  them (compromised agent, weak admin path).
- Database and mail integrations (SQL sinks, SMTP) for injection / resource abuse.

## Components that matter most / least

**Highest priority (remote / privilege boundaries):**

- `src/os_csyslogd`, `src/os_auth` (`ossec-authd` / `agent-auth`), `src/remoted`
- `src/analysisd` (decoders, rules engine, accumulators, JSON/XML parsers)
- `src/os_crypto` (shared keys, encryption, hashing)
- `src/shared` network/queue helpers used across daemons
- `src/os_xml`, `src/os_regex` (untrusted structured input)

**High priority (local root / integrity):**

- `src/syscheckd` (realtime FIM, Windows registry, diff/seechanges)
- `src/logcollector` (file/command/eventchannel readers)
- `src/rootcheck`
- `src/os_execd` (active response command execution)
- `src/client-agent` / agent daemon paths that run as SYSTEM/root

**Lower priority / out of preference unless they enable the above:**

- Packaging, init scripts, and pure documentation under `doc/`, `contrib/`
  samples that are not linked into daemons
- Bundled third-party trees under `src/external/` (zlib, Lua, cJSON, PCRE2
  sources) — prefer reporting bugs in OSSEC wrappers/callers; upstream-only
  issues in unmodified external code are out of scope unless OSSEC’s build
  flags or patches introduce them
- Windows UI cosmetics (`win32ui`) unless they affect agent security config or
  key handling

## How to exercise it

- Manager binaries after the Dockerfile build live under `/src/src/` (DEBUG
  `TARGET=server`) and copies under `/src/.oss-scanner/bin/server/`.
- Agent binaries are under `/src/.oss-scanner/bin/agent/`.
- Unit tests: `make -C /src/src TARGET=server run_tests` (also built during
  the image build).
- Useful local drivers: `ossec-logtest` / analysisd test bits, `ossec-regex`,
  authd/agent-auth registration flows, remoted protocol framing, syscheck
  realtime on a disposable directory, decoder/rule corpora under `etc/` and
  `rules/`.
- Prefer crafted protocol bytes, decoder inputs, and FIM edge cases over
  full multi-host installs when demonstrating a bug.

## How you rate severity

- **Critical:** unauthenticated remote code execution or memory corruption in
  remoted/authd/analysisd reachable from the network; authd key compromise
  that lets an attacker enroll or impersonate agents; active-response
  command injection as root from attacker-controlled alert fields.
- **High:** authenticated-agent → manager memory corruption or logic bugs that
  yield RCE/DoS of the manager; privilege escalation from agent/ossec user to
  root; crypto/key-handling flaws that forge agent messages; reliable crash
  of remoted/analysisd from a single agent or packet.
- **Medium:** significant DoS (manager hang/OOM from one agent), important
  information disclosure (keys, sensitive file contents via FIM/diff bugs),
  sandbox/path escape in FIM or logcollector that stays local.
- **Low:** hard-to-reach crashes requiring privileged local config write,
  purely cosmetic parser quirks, missing hardening without a concrete bug.

Memory unsafety (buffer overflow, UAF, double-free, uncontrolled format
string) in network-facing or root daemons should be at least **high** when
reachable; escalate to **critical** when unauthenticated or clearly
exploitable for RCE.

## Report and patch preferences

- Prefer minimal, demonstrated reproducers (packet, log line, file name, or
  small C driver) over speculative reports.
- Candidate patches should be small and consistent with existing OSSEC style;
  say when a fix needs a config compatibility note.
- Deduplicate by root cause (same parser sink or queue bug), not by every
  similar crash site.

## Anything to leave alone

- Do not treat “OSSEC runs as root” or “agents are trusted once keyed” by
  themselves as vulnerabilities; focus on reachable bugs that break those
  assumptions.
- Do not report missing modern compiler flags alone without a defect.
- Do not file Windows-only packaging / SxS redistributable issues unless they
  create a security boundary bypass.
- Rule/decoder content quality (noisy alerts, missed attacks) is product
  tuning, not a vulnerability, unless a rule/decoder bug causes a safety or
  integrity failure in the engine itself.
