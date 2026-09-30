# syntax=docker/dockerfile:1
# node:24-alpine, resolved 2026-09-28
FROM node:26-alpine@sha256:0b36e8c136b94cd4fcf02188228e76c31ad5872eef3fec8cbd2eee500cfd9e80 AS base
WORKDIR /app

FROM base AS deps
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

FROM base AS runtime
# The runtime only ever runs `node`; npm, npx, corepack and yarn (with their bundled dependencies) are not needed and only add attack surface.
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack       /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack /opt/yarn-* /usr/local/bin/yarn /usr/local/bin/yarnpkg
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION=0.6.0
LABEL org.opencontainers.image.title="AKAC gateway" \
      org.opencontainers.image.description="Agent Knowledge Access Control reference gateway" \
      org.opencontainers.image.source="https://github.com/oemer-coskun/AKAC" \
      org.opencontainers.image.licenses="MIT-0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.vendor="AKAC project"

COPY --from=deps /app/node_modules ./node_modules
COPY package.json package-lock.json ./
COPY --chown=1000:1000 . .
RUN mkdir -p /app/data && chown -R 1000:1000 /app/data /app

# Non-root, numeric UID (works with runAsNonRoot + runAsUser: 1000, no /etc/passwd lookup needed)
USER 1000:1000

ENV HOST=0.0.0.0 \
    PORT=8787 \
    NODE_ENV=production

EXPOSE 8787
EXPOSE 8788
EXPOSE 9464

HEALTHCHECK --interval=10s --timeout=3s --retries=5 --start-period=10s \
  CMD ["node", "-e", "fetch('http://127.0.0.1:8787/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]

# No shell entrypoint: exec form, node is PID 1 directly.
CMD ["node", "reference/server.ts"]
