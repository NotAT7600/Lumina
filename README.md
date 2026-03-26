# Lumina - Autonomous Penetration Testing Platform

Lumina is an AI-orchestrated penetration testing platform that combines a LangGraph state machine, industry-standard security tooling, and LLM interpretation into a single automated pipeline. Point it at a web target or a local repository and it will fingerprint the stack, dynamically select the relevant scanners, interpret raw tool output with an LLM, build an attack chain graph, and deliver a structured vulnerability report — all streamed live to the UI.

## How it works

A **planner node** inspects the target first:

- **URL targets** — runs a quick pre-scan fingerprint (httpx + whatweb) and uses LLM-driven adaptive planning to select relevant web agents. Under uncertain signal (timeouts/connection issues/localhost), guardrails keep a safe baseline of recon + SQL injection + XSS before attack chain + report.
- **Repository targets** — walks the file tree, builds a fingerprint, and asks the LLM to choose only the relevant agents from: `static_c`, `static`, `deps_py`, `deps_js`, `secrets`.

Each selected **agent node** runs its toolset, skips the LLM call if the tools fail to produce output, and accumulates structured findings into shared graph state. After all scan agents complete, an **attack chain node** reasons over the combined findings to produce a causal MITRE-aligned exploit graph. A final **report node** synthesises everything into a Markdown vulnerability report.

LLM token streaming is pushed to the frontend in real time via SSE throughout every node.

## Agent pipeline

| Agent                 | Tools                        | Target type |
| --------------------- | ---------------------------- | ----------- |
| Planner               | LLM + file-tree fingerprint  | both        |
| Recon                 | httpx · nmap · whatweb       | URL         |
| SQL Injection         | sqlmap                       | URL         |
| XSS                   | dalfox                       | URL         |
| C/C++ Static Analysis | cppcheck · semgrep p/c       | repo        |
| Static Analysis       | semgrep · bandit             | repo        |
| Python Deps           | pip-audit                    | repo        |
| JS Deps               | npm audit                    | repo        |
| Secrets               | trufflehog · detect-secrets  | both        |
| Attack Chain          | LLM reasoning (MITRE ATT&CK) | both        |
| Report                | LLM synthesis                | both        |

## LLM providers

Set `LLM_PROVIDER` in your environment to switch backends:

| Provider           | Env var              | Default model                              |
| ------------------ | -------------------- | ------------------------------------------ |
| `ollama` (default) | `OLLAMA_MODEL`       | `llama3.1:8b`                              |
| `openai`           | `OPENAI_MODEL`       | `gpt-4o`                                   |
| `claude`           | `ANTHROPIC_MODEL`    | `claude-sonnet-4-6`                        |
| `featherless`      | `FEATHERLESS_MODEL`  | `meta-llama/Meta-Llama-3.1-8B-Instruct`   |

## Prerequisites

- **Docker & Docker Compose** — runs the backend and all security binaries inside Linux containers
- **pnpm** — runs the Next.js frontend natively
- **Ollama** (if using the default local LLM) — must be running on your host machine. On macOS, run `launchctl setenv OLLAMA_HOST "0.0.0.0"` before starting Ollama so the backend container can reach it via `host.docker.internal`.

## Quick start (development)

The development setup runs the backend inside Docker (for the security tools) and the frontend natively (for fast hot-reload). Your local Ollama instance is used for LLM inference.

### 1. Start the backend and test target

```bash
docker compose -f docker-compose.dev.yml up -d --build
```

- Backend API: `http://localhost:8000`
- OWASP Juice Shop test target: `http://localhost:3001`

The backend volume-mounts `./backend` so Python code changes hot-reload without a rebuild. If you change environment variables, prompts, or the Dockerfile, restart the container:

```bash
docker restart lumina-dev-backend
```

### 2. Start the frontend

```bash
pnpm install
pnpm dev
```

Frontend: `http://localhost:3000`

## Scanning targets

**Web target (Juice Shop):**
Because the backend runs inside Docker's network, use the container alias rather than `localhost`:

```
http://host.docker.internal:3001
```

**Public GitHub repository:**
Submit a repository root URL directly:

```
https://github.com/owner/repository
```

Lumina clones the repository inside the backend container runtime (named Docker
volume mounted at `/var/lumina/repos`) and scans that snapshot. Nothing is
cloned into your local workspace.

**Local repository:**
Mount the repo into `/tmp` on your host and submit the container-side path:

```bash
cp -r /path/to/your/repo /tmp/myrepo
# Submit: /tmp/myrepo
```

The dev compose file mounts `/tmp` and `/Users` read-only into the backend container.

## Useful Docker commands

```bash
# Stream backend logs
docker logs lumina-dev-backend -f

# Restart backend (after env/prompt changes)
docker restart lumina-dev-backend

# Stop everything
docker compose -f docker-compose.dev.yml down
```

## Full stack (all-in-Docker, including Ollama and frontend)

For a fully containerised deployment (no local dependencies):

```bash
docker compose up -d --build
```

This spins up Ollama, the backend, the Next.js frontend, and Juice Shop all within a shared Docker network.
