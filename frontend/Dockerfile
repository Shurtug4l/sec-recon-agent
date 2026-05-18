# syntax=docker/dockerfile:1.7

# ============================================================================
# Builder: install dependencies and build Next.js in standalone mode.
# ============================================================================
FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
# Deterministic install: `npm ci` refuses to mutate package.json or the
# lockfile, so any drift fails the build instead of being silently papered
# over. --legacy-peer-deps absorbs the Next 15 / React 19 peer-tag mismatch
# (RC tag on the dep range, GA in the wild).
RUN npm ci --no-audit --no-fund --legacy-peer-deps

FROM node:22-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

# ============================================================================
# Runtime: minimal Node image with the standalone Next.js server.
# ============================================================================
FROM node:22-alpine AS runtime

# node:22-alpine ships with a `node` user (uid 1000) — reuse it instead
# of creating a parallel one (the explicit `adduser` would collide on gid 1000).
RUN apk add --no-cache curl tini

WORKDIR /app

# Standalone output ships everything the server needs in /app.
COPY --from=builder --chown=node:node /app/.next/standalone ./
COPY --from=builder --chown=node:node /app/.next/static ./.next/static

ENV NEXT_TELEMETRY_DISABLED=1 \
    NODE_ENV=production \
    PORT=3000 \
    HOSTNAME=0.0.0.0

USER node

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://localhost:3000/ || exit 1

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "server.js"]
