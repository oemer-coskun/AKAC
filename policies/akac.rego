package akac

import rego.v1

# Reference company policy. An allow here NEVER overrides the deterministic core.
default allow := false

# Immutable deployment revision. Changing rules requires a new revision.
decision := {"allow": allow, "revision": "akac-company/0.2"}

allow if {
    input.tenant == "acme"
    input.purpose == "work"
    input.action in {"read", "derive", "write_memory", "share", "export"}
    input.classification in {"public", "internal", "confidential", "restricted"}
}
