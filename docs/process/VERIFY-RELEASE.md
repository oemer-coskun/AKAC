# Verifying a release

Applies to releases built by `.github/workflows/release.yml` (decision:
[ADR-017](../../governance/ADR-017-supply-chain-and-release-integrity.md)). Releases before the first
one built by that workflow (v0.4.0, v0.5.0) do not carry the source assets below; their image was
signed and attested by the earlier workflow. Nothing here has been checked by a third party, and the
SLSA Build L3 statement is the project's own assessment.

Set the variables once:

```sh
TAG=v0.6.0                                   # the release you verify
REPO=oemer-coskun/AKAC
IMAGE=ghcr.io/oemer-coskun/akac
ISSUER=https://token.actions.githubusercontent.com
IDENTITY="https://github.com/$REPO/.github/workflows/release.yml@refs/tags/$TAG"
```

## What a release contains

| Asset | Meaning |
|---|---|
| `akac-$TAG.tar.gz` | source tarball (`git archive`, `gzip -n`): bytes depend only on the commit |
| `akac-$TAG.sbom.cdx.json` | CycloneDX SBOM of the dependency tree (`npm sbom`) |
| `akac-$TAG.tar.gz.sigstore.json`, `akac-$TAG.sbom.cdx.json.sigstore.json` | cosign keyless bundles (signature, certificate, transparency-log entry) |
| `akac-$TAG.intoto.jsonl` | SLSA provenance for the tarball and the SBOM (slsa-github-generator, generic) |
| `akac-$TAG.SHA256SUMS` | checksums of the assets above |
| Image `$IMAGE:<version>` | multi-arch container image; signature, attestations, SBOM and SLSA provenance are stored in the registry next to it |

## 1. Source tarball and SBOM

```sh
gh release download "$TAG" --repo "$REPO" --dir rel && cd rel
sha256sum -c "akac-$TAG.SHA256SUMS"

# cosign bundle (keyless): checks signature, certificate identity and the transparency log
for f in "akac-$TAG.tar.gz" "akac-$TAG.sbom.cdx.json"; do
  cosign verify-blob --bundle "$f.sigstore.json" \
    --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER" "$f"
done

# SLSA provenance (slsa-verifier)
slsa-verifier verify-artifact "akac-$TAG.tar.gz" \
  --provenance-path "akac-$TAG.intoto.jsonl" \
  --source-uri "github.com/$REPO" --source-tag "$TAG"

# GitHub artifact attestation
gh attestation verify "akac-$TAG.tar.gz" --repo "$REPO"

# SBOM sanity
jq -r '.bomFormat, .specVersion, (.components | length)' "akac-$TAG.sbom.cdx.json"
```

## 2. Container image

Resolve the digest once and verify by digest, never by tag:

```sh
DIGEST=$(docker buildx imagetools inspect "$IMAGE:${TAG#v}" --format '{{json .Manifest.Digest}}' | tr -d '"')

cosign verify "$IMAGE@$DIGEST" \
  --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER"

slsa-verifier verify-image "$IMAGE@$DIGEST" \
  --source-uri "github.com/$REPO" --source-tag "$TAG"

gh attestation verify "oci://$IMAGE@$DIGEST" --repo "$REPO"
```

A failed command means do not run the image. Success means the artifact was produced by that
workflow at that tag in that repository; it does not mean the code is free of vulnerabilities or
that the workflow definition was reviewed by anyone but the maintainers.

## 3. Reproducing the builds

Tarball (expect the same SHA-256 as in `SHA256SUMS`):

```sh
git clone https://github.com/$REPO.git && cd AKAC && git checkout "$TAG"
git archive --format=tar --prefix="akac-$TAG/" HEAD | gzip -n -9 | sha256sum
```

The result depends on the `git archive` and gzip implementations (zlib level 9). A different gzip
build can produce different compressed bytes for the same tar; compare the uncompressed tar digest
if it does.

Image (single platform, attestations off, as CI checks on every push):

```sh
export SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)
docker buildx build --no-cache --provenance=false --sbom=false \
  --build-arg VERSION="$TAG" --build-arg VCS_REF="$(git rev-parse HEAD)" \
  --build-arg SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
  --output type=oci,dest=akac.tar,rewrite-timestamp=true .
tar -xOf akac.tar index.json | jq -r '.manifests[0].digest'
```

Compare with the per-platform manifest digest of `linux/amd64` in the released image
(`docker buildx imagetools inspect "$IMAGE@$DIGEST" --raw`). The multi-arch index digest is not
comparable because it lists attestation manifests that contain run-specific data.

What can differ, honestly: a different BuildKit version (layer compression choices), the `arm64`
image (built under emulation and not compared in CI), base-image tag drift (the base is pinned by
digest, so only a changed pin changes the result) and `npm ci` output if the registry serves
different tarball bytes for a locked version (the lockfile pins integrity hashes, so that would
fail the install rather than change the image silently). CI job: `reproducible-build` in
`.github/workflows/ci.yml`.

## Reporting a verification failure

A signature or provenance that fails to verify for a published release is a security report:
[SECURITY.md](../../SECURITY.md).
