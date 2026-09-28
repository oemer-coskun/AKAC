# Security policy

This is a draft reference implementation. No version currently has a production
support commitment or independent security certification.

Report suspected vulnerabilities through GitHub's private vulnerability reporting
feature when enabled. If unavailable, open an issue requesting a private channel
without including exploit details, secrets or real company data. The maintainer
will arrange a private disclosure path. No response-time SLA is promised.

Include affected commit, deployment profile, trust assumptions, minimal synthetic
reproduction, expected versus actual authorization and disclosure impact. Never
test against systems you do not own or have permission to assess.

Do not rely on the gateway alone to isolate model sessions, block direct network
access, enforce retention or protect compromised administrative credentials. Read
`docs/THREAT-MODEL.md` before any deployment.
