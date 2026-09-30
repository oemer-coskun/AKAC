# Ömer Hüseyin Coşkun — AI Architect

I design and build production-oriented enterprise AI platforms, from requirements and system architecture to agentic workflows, permission-aware RAG, security, infrastructure and observability. AKAC is my answer to one question every enterprise AI system eventually faces: *what may an agent know, derive, remember and disclose?*

| | |
|---|---|
| Email | [mail@oemer-coskun.de](mailto:mail@oemer-coskun.de) |
| Website | [oemer-coskun.de](https://oemer-coskun.de) |
| LinkedIn | [linkedin.com/in/oemer-coskun53](https://www.linkedin.com/in/oemer-coskun53) |
| GitHub | [github.com/oemer-coskun](https://github.com/oemer-coskun) |

Get in touch about AI architecture work, adopting AKAC, the separately available industry profiles, the enterprise edition, independent reviews or collaboration. Security vulnerabilities go through [SECURITY.md](SECURITY.md), not email or public issues.

## Role and focus

**AI Architect**, co-founder and AI engineer at SiegFlow AI. About eleven years around software engineering, the last four focused on AI engineering and generative AI systems.

- **Agentic AI:** multi-agent orchestration with explicit state, tool permissions, scopes, budgets and human approval gates.
- **Enterprise knowledge and RAG:** permission-aware retrieval, persistent organizational memory, source grounding and provenance.
- **AI security and access control:** RBAC/ABAC, tenant isolation, least privilege, policy engines, verifiable audit, threat modelling at data, model and tool boundaries.
- **Platform and systems architecture:** enterprise, solution and platform architecture, event-driven and distributed systems, cloud, hybrid and on-premises AI runtimes.

## Highlights

| Project | What it is | Evidence |
|---|---|---|
| **AKAC — Agent Knowledge Access Control** (author) | Open specification and reference gateway for access control over AI agent knowledge: derived content inherits its sources' restrictions, retrieval is pre-filtered and re-checked, every decision is verifiable. | [This repository](README.md): 577 CI tests on PostgreSQL/pgvector and OPA, 629 conformance vectors with zero leaks, bounded TLA+ model, mutation score 94.76%, second implementation in Python |
| **SIP — Agentic Enterprise Platform** (SiegFlow AI) | Modular no-code platform for autonomous B2B processes: agents, RAG, multi-LLM routing, persistent knowledge and role-based access. Authorization runs outside the model through deterministic, fail-closed gates. | Product architecture: State → Action → Authority → Execution → Feedback |
| **Agentic Software Factory** (SiegFlow AI) | Planner, builder, independent reviewer and security reviewer agents in controlled LangGraph workflows with mandatory tests, quality and security gates and human approval. | CI/CD with type checks, unit/API/E2E tests and traceable approvals |
| **Enterprise AI Runtime** | Distributed LLM and agent workloads on AWS Bedrock, Azure and Kubernetes with multi-LLM routing, GPU isolation (NVIDIA MIG), Triton model serving and full observability. | Latency, throughput, GPU, cost and quality monitoring |
| [**green-but-blind**](https://github.com/oemer-coskun/green-but-blind) | Open-source scanners that find tests which pass without testing anything, and invisible control characters that break code. | Public repository |
| [**cite-or-decline**](https://github.com/oemer-coskun/cite-or-decline) | Retrieval that cites file, page and line for every answer and declines when the corpus holds no answer. | Public repository |

## How I work

1. **Discover and architect.** Requirements engineering and target-state design; system boundaries, decisions and verification criteria captured in ADRs, SysML v2 models and API/event contracts.
2. **Plan → Build → Verify → Review.** Explicit planning, implementation, automated verification and independent review, including agent-assisted development with controlled permissions and approval boundaries.
3. **Authority outside the model.** Agents act within IAM/RBAC rules, scopes, budgets and tenant boundaries; decisions that matter are deterministic and fail closed.
4. **Evidence over claims.** Conformance vectors, property-based and mutation testing, formal models, threat models and measurable non-functional requirements. Every claim links to a result.
5. **Operate what you build.** Telemetry, traces and security findings feed controlled remediation; changes pass CI/CD, tests, security gates and human approval before rollout, with tested rollback.

## Tech stack for AI architecture

| Area | Tools and practices |
|---|---|
| Agentic AI and GenAI | LangGraph, LangChain, Agno, Model Context Protocol (MCP), RAG, persistent memory, human-in-the-loop, prompt and context engineering, AI evaluation |
| Models and serving | PyTorch, Hugging Face Transformers, AWS Bedrock, Azure, multi-LLM routing, Triton, NVIDIA MIG |
| Access control and security | RBAC/ABAC, OPA, OpenID AuthZEN, OAuth 2.0 token exchange, DPoP, row-level security, verifiable audit (RFC 9162), post-quantum signatures, threat modelling (STRIDE, LINDDUN) |
| Application engineering | Python, FastAPI, TypeScript, Node.js, PostgreSQL, pgvector, SQL, REST/OpenAPI, webhooks, event contracts |
| Platform and infrastructure | Kubernetes, Helm, Docker, Terraform, GitHub Actions, cloud, hybrid and on-premises runtimes, autoscaling, controlled rollouts |
| Observability and LLMOps | OpenTelemetry, Langfuse, MLflow, Prometheus, DCGM, latency, cost and quality monitoring |
| Quality and DevSecOps | PyTest, Playwright, fast-check, StrykerJS, TLA+/TLC, CodeQL, SBOM, container and secret scanning, SLSA provenance, Sigstore |
| Architecture methods | ADRs, SysML v2, requirements engineering, event-driven and distributed systems, state machines |

Languages: German and Turkish (native), English (C1).
