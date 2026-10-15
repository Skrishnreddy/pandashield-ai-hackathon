# PandaShield AI - Hackathon Edition: single Cloud Run service
# (React frontend built into static files, served by the Node API).

FROM node:22-slim AS frontend
WORKDIR /build/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM node:22-slim AS backend-deps
WORKDIR /build/backend
COPY --chown=node:node backend/package.json backend/package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund

FROM node:22-slim
ENV NODE_ENV=production PORT=8080 \
    STATIC_DIR=/app/frontend/dist SAMPLES_DIR=/app/samples
WORKDIR /app
COPY --chown=node:node --from=backend-deps /build/backend/node_modules ./backend/node_modules
COPY --chown=node:node backend/package.json ./backend/package.json
COPY --chown=node:node backend/src ./backend/src
COPY --chown=node:node --from=frontend /build/frontend/dist ./frontend/dist
COPY --chown=node:node samples ./samples
USER node
EXPOSE 8080
CMD ["node", "backend/src/server.js"]
