# AKAC: Agent Knowledge Access Control

**Access control for what AI agents may know, derive, remember and share in the enterprise.**

**Contact:** [CONTACT.md](CONTACT.md) · [mail@oemer-coskun.de](mailto:mail@oemer-coskun.de)

## The problem

AI agents read company knowledge, combine it, write summaries and memories, and pass results to people, tools and other agents. Classic role-based access control decides who may open a document. It does not decide what an agent may do with what it has read, or who may see what it produces from it.

Typical gaps in enterprise AI and RAG deployments:

- Confidential content reaching users or agents who are not cleared for it through retrieval, summaries or agent memory.
- Knowledge graphs and GraphRAG pipelines without per-user access control.
- Multi-agent workflows in which content moves between agents without control.
- No verifiable record of which knowledge an AI answer was based on.

## What AKAC offers

AKAC is a security architecture and product for knowledge access by AI agents, designed by Ömer Hüseyin Coşkun and first published on 2026-09-28.

- **Permission-aware RAG and GraphRAG:** agents only work with knowledge the user and the agent are both allowed to see.
- **Protection of derived knowledge:** summaries, memories and other agent outputs stay protected according to the sources they came from.
- **Multi-agent and delegation control:** controlled handover between agents, tools and recipients.
- **Verifiable audit:** traceable and tamper-evident evidence of AI decisions for compliance and audits.
- **Integration:** works alongside existing identity, policy and data platforms and common agent frameworks.

## Security classes

| Class | Typical use |
|---|---|
| SK-1 Basis | Internal assistants over non-regulated content |
| SK-2 Enterprise | Company-wide and multi-tenant deployments |
| SK-3 Regulated | Finance, health, legal and insurance |
| SK-4 High-Assurance | Critical infrastructure, export-controlled material, crown-jewel IP |

## Services

- AI security architecture and assessments for RAG, GraphRAG and multi-agent systems.
- AKAC implementation, integration and operation per security class.
- Industry-specific profiles and enterprise components.

Specification, implementation and evidence are available to customers and partners under agreement. Inquiries: [CONTACT.md](CONTACT.md).

## License

Copyright 2026 Ömer Hüseyin Coşkun. All rights reserved. See [LICENSE](LICENSE).
