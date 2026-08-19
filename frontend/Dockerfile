# frontend/Dockerfile — Next.js 14 dashboard (standalone output).
#
# Phase 16 (Prompt 307-308): the frontend image used by the Skaffold local
# dev loop. Multi-stage: pnpm deps+build -> the minimal standalone server.
# The final stage is a distroless-style node runtime.
#
# Build from the MONOREPO ROOT: frontend is a pnpm workspace member whose
# lockfile lives at the root (pnpm-lock.yaml, pnpm-workspace.yaml).
#   docker build -f frontend/Dockerfile .
#
# Install and build share one stage on purpose: the pnpm store is hundreds
# of MB of small files, and a cross-stage `COPY --from=deps .../node_modules`
# of that tree is both slow and fragile on Docker Desktop (daemon EOFs under
# load). Only the small build outputs (.next/standalone, .next/static) cross
# into the runner stage. The install layer is still cached independently
# (inputs: the three manifest copies), so source edits rebuild only the
# compile steps.
#
# Node 22 LTS + pnpm 10.4.1 (the version pinned by `packageManager` in the
# monorepo root): pnpm >= 11 requires newer Node builtin modules and fails
# on Node 20 with ERR_UNKNOWN_BUILTIN_MODULE.

FROM node:22-alpine AS build
WORKDIR /app
RUN corepack enable && corepack prepare pnpm@10.4.1 --activate
# Workspace manifests + lockfile first (layer caching keeps install isolated).
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY frontend/package.json ./frontend/
COPY blockchain/package.json ./blockchain/
RUN pnpm install --frozen-lockfile --prod=false
# Full source (context is whitelisted by .dockerignore — a few MB, no caches).
COPY . .
# Standalone build (output: "standalone" in next.config.mjs), frontend package only.
RUN pnpm --filter @flare-verifiable-rag/frontend build

FROM node:22-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
RUN addgroup -S nodejs && adduser -S nextjs -G nodejs

# The standalone server + static chunks are the only things that cross into
# the runner (no node_modules, no source). The app ships no public/ dir today;
# when it does, add a COPY --from=build /app/frontend/public /app/frontend/public.
#
# pnpm-workspace note: Next.js standalone output preserves the workspace layout,
# so the app root lands at /app/frontend (server.js, package.json, node_modules)
# inside the standalone dir — the entrypoint and static path must be app-relative.
COPY --from=build /app/frontend/.next/standalone/. /app/
COPY --from=build /app/frontend/.next/static /app/frontend/.next/static
RUN chown -R nextjs:nodejs /app

USER nextjs
EXPOSE 3000
ENV PORT=3000
CMD ["node", "frontend/server.js"]
