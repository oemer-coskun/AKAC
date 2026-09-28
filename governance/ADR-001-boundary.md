# ADR-001: Immutable core plus narrowing policy

Status: accepted for reference 0.1.

The core implements the specification's mandatory safety invariants. Company
policy runs afterward and can only narrow an allow. This prevents an incorrectly
permissive policy bundle from bypassing tenant isolation, grant expiry or source
inheritance. Other implementations may use a different engine if their observable
semantics satisfy the profile. OPA is not a normative dependency.

Trade-off: company exceptions cannot override the core. New supported exceptions
require an explicit specification/profile change and tests.
