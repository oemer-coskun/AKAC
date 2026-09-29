# Errata log

Corrections to published specification text that do not change normative behaviour. A change
that alters what an implementation MUST, MUST NOT or SHOULD do is not an erratum; it follows
[CHANGE-CONTROL.md](CHANGE-CONTROL.md) and appears in the changelog and a migration guide.

Each entry: an identifier, the affected document and location as published, the defect, the
correction, the release that contains the corrected text, and whether the correction affects
normative behaviour. Errata are added by pull request; entries are never deleted, only
marked as superseded.

| ID | Document (published location) | Defect | Correction | Fixed in | Normative effect |
|---|---|---|---|---|---|
| E-0001 | [CONFORMANCE.md](CONFORMANCE.md), cross-tenant vector tagging (published in 0.5.0) | The text allowed a cross-tenant vector to be identified by "an id naming the tenant" in addition to the tag. R105 in [AKAC-0.4.md](AKAC-0.4.md) and the reference runner identify such a vector by the tag only. | The clause is removed; the tag is the only identifier. | 0.6.0 | None. Aligns the text with R105. |
| E-0002 | [AKAC-0.4.md](AKAC-0.4.md), Destinations, closing paragraph of R60-R71 (published in 0.5.0) | A sentence was duplicated, and the list of requirements that deny with the reason code `RECIPIENT` included R64 and R68, while R68 specifies `INVALID_DELEGATION`. | The duplicated sentence is removed; the list names R62, R63, R66 and R67. | 0.6.0 | None. R68 already required `INVALID_DELEGATION`. |
| E-0003 | [AKAC-0.5.md](AKAC-0.5.md), reference to `docs/RUNTIME-CONTAINMENT.md` (published in 0.5.0) | The relative link resolved to a path outside the repository (`../../docs/...`). | The link is `../docs/RUNTIME-CONTAINMENT.md`. | 0.6.0 | None. |
| E-0004 | [AKAC-0.4.md](AKAC-0.4.md), R58 and R94 (published in 0.4.0) | Lowercase "must" and "must not" appeared in requirement text, where only the uppercase keywords are normative. | Rephrased ("an operation that changes a whole lineage"; R94 title "Cache keys not derived from protected content alone"; "the purpose is that an adversary who observes a key does not thereby learn ..."). | 0.6.0 | None. The normative keywords of both requirements are unchanged. |
| E-0005 | [CONFORMANCE.md](CONFORMANCE.md), Running (published in 0.5.0) | The fixture was said to be defined in `examples/fixture.ts`. | From 0.6 the fixture is the data file `examples/fixture.json` (R127); `examples/fixture.ts` only loads it. | 0.6.0 | None. The records are identical. |

Reporting an erratum: open an issue with the label `erratum` giving the document, the location
and the proposed correction. If the report also concerns a security-relevant ambiguity, follow
[SECURITY.md](../SECURITY.md) instead.
