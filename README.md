# sast-agent

[![CI](https://github.com/openasy/sast-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/openasy/sast-agent/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue)](./LICENSE)

The agent of [OpenAsy SAST](https://github.com/openasy/sast). SAST follows the repositories of a GitHub account and
queues a scan when a default branch moves; the agent clones each one, scans it with
[Opengrep](https://github.com/opengrep/opengrep) and sends the findings back as SARIF. **SAST holds no source code
and no scanner** (ADR 0036).

- **Code is untrusted input.** Every job is checked before anything runs (an https clone URL without credentials, a
  branch name, a commit hash). Git runs without a shell, hooks, symlinks or submodules, and fetches exactly the commit
  SAST queued. Opengrep parses the code and never runs it, as the unprivileged `node` user, with a memory limit per
  file and a time limit per scan.
- **Nothing stays.** The clone goes to `/scan`, a tmpfs, and is deleted after each scan, whether it worked or not.
- **The forge token stays out of sight.** It reaches git only as a header in git's environment: never in an
  argument, a URL, Opengrep's environment or a log line. An error from git is scrubbed of it all the same.
- **It connects out, never in.** It enrols once with a one-time token and then uses its own secret, kept in
  `/data/agent.state` and sealed with its own key-encryption key, since that secret fetches jobs and jobs carry
  tokens. When SAST is down it keeps asking and says so in `/readyz`.

## Run

Add the agent in SAST under GitHub, Agents. It shows a one-time enrolment token and this command:

```bash
openssl rand -hex 32 > openasy-agent-kek   # keep it with your backups
docker run -d --name sast-agent --restart unless-stopped --read-only --tmpfs /scan:exec,size=2g,uid=1000,gid=1000 \
  --cap-drop ALL --security-opt no-new-privileges --memory 3g \
  -v sast-agent-data:/data -v "$PWD/openasy-agent-kek:/run/secrets/openasy-agent-kek:ro" \
  -e SAST_URL=https://sast.example.com -e SAST_ENROLL_TOKEN=ose_... \
  ghcr.io/openasy/sast-agent:0.7.0
```

The agent needs to reach SAST and the forge (`github.com`, or your GitHub Enterprise address) and nothing else; give
it a network that allows only those. The size of `/scan` is the largest repository it can clone. It must allow `exec`, because Opengrep unpacks itself there and runs, and Docker mounts a tmpfs `noexec` otherwise. The agent must be
the same version as SAST (ADR 0019).

| Variable | Default | |
| --- | --- | --- |
| `SAST_URL` | | Where SAST is, such as `http://sast:8080` or its https:// address |
| `SAST_ENROLL_TOKEN` | | One-time, for the first start only |
| `SAST_AGENT_SECRETS_KEY_FILE` | `/run/secrets/openasy-agent-kek` | 32-byte key that seals the agent's secret |
| `SAST_AGENT_STATE` | `/data/agent.state` | The sealed state, on its volume |
| `POLL_SECONDS` | `10` | How often it asks for work when the queue is empty |
| `WORK_DIR` | `/scan` | Where clones go; mount a tmpfs here |
| `CLONE_TIMEOUT_MINUTES` | `5` | Time limit for a clone or a rule source |
| `SCAN_TIMEOUT_MINUTES` | `20` | Time limit for one scan |
| `SCAN_MEMORY_MB` | `2048` | Opengrep's memory limit per file |
| `PORT` | `9100` | `/healthz`, `/readyz` and `/metrics` |

## Rules

The rules in [`rules/`](./rules) are written for OpenAsy and ship under this repository's licence, so every OpenAsy
user may run them. Each has a test file with code it must flag (`ruleid:`) and code it must not (`ok:`), run in CI.

| Language | Rules |
| --- | --- |
| JavaScript and TypeScript | eval and `new Function`, shell commands built from data, SQL built from data, TLS checks off, HTML from data |
| Python | eval and exec, shell commands, pickle and `yaml.load`, SQL built from data, TLS checks off, MD5 and SHA-1 |
| Go | shell commands, SQL built from data, `InsecureSkipVerify` |
| Java | `Runtime.exec` and shell commands, `ObjectInputStream` and `XMLDecoder`, SQL built from data |

Rule files an install writes in SAST under Rules come with each job and are scanned with the others, and rules
switched off there are skipped with `--exclude-rule`, whichever file they come from.

An install may add rule sources in SAST under GitHub, Rule sources: public git repositories over https, fetched for each
scan. Only YAML files with a top-level `rules:` key are used. A rule source is the install's choice and
responsibility, including its licence; `opengrep/opengrep-rules`, for example, carries the Commons Clause.

## Develop

```bash
npm install
npm test                                        # jobs, git, the scan and the loop, against a local repository
OPENGREP_BIN=/path/to/opengrep npm test         # and the shipped rules with the real engine
npm run test:rules                              # each rule against its test file (needs opengrep on PATH)
```

## Licence

AGPL-3.0 (ADR 0008).
