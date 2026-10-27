# syntax=docker/dockerfile:1
FROM node:22-slim AS builder
WORKDIR /app
# VITE_API_URL is inlined into the client bundle at build time (Vite
# convention) — it cannot be changed by a container-runtime env var, so it
# must be a build arg. Defaults to the host loopback, which is correct for
# the standard `docker compose up` flow: the browser (not the frontend
# container) makes this request, and the api service publishes 8000 on
# the host.
ARG VITE_API_URL=http://localhost:8000
ENV VITE_API_URL=${VITE_API_URL}
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

FROM node:22-slim AS runtime
WORKDIR /app
RUN useradd --create-home insyte
COPY --from=builder --chown=insyte:insyte /app/node_modules ./node_modules
COPY --from=builder --chown=insyte:insyte /app/dist ./dist
COPY --from=builder --chown=insyte:insyte /app/server.mjs ./server.mjs
COPY --from=builder --chown=insyte:insyte /app/public ./public

USER insyte
ENV PORT=3000 HOST=0.0.0.0
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD node -e "fetch('http://localhost:3000/').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "server.mjs"]
