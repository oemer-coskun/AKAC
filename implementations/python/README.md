# Python decision evaluator

A second implementation of the AKAC decision function using only Python 3.10+
standard library. It discovers the source graph and computes path heights by
leaf elimination; TypeScript uses memoized traversal. It does not import the
TypeScript policy code. This is same-project differential evidence, not an
independently authored external implementation or a complete gateway.

Protocol: read one JSON document on stdin with a `cases` array. Each case contains
`state` (the reference state format) and `request` (binding, action, resource,
purpose, now). Write a JSON array of `{effect, code}` decisions to stdout.

```sh
python3 implementations/python/akac.py < cases.json
node --test tests/interop.test.ts
```

The test generates 1,000 fixed-seed cases plus an explicit positive control,
compares complete decisions, and checks 500 clearance-monotonicity cases. It
covers authorization decisions, not persistence, HTTP, OPA, JWT or runtime release.
