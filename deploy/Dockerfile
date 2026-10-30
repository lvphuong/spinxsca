# spinxsca service image (ADR-034). Build from the repository root:
#   docker build -f deploy/Dockerfile -t spinxsca .
# Scanners run as sibling containers through the host Docker daemon, so the image carries the Docker
# CLI and the data directory must be bind-mounted at the same path on the host (see compose file).

FROM node:24-bookworm-slim AS build
# better-sqlite3 has no prebuilt binary for every platform (e.g. linux/arm64 on Node 24): build tools
# stay in this stage only.
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 make g++ ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/spinxsca
COPY . .
RUN corepack enable \
 && pnpm install --frozen-lockfile \
 && pnpm build

FROM docker:28-cli AS docker-cli

FROM node:24-bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=build /opt/spinxsca /opt/spinxsca
ENV SPINXSCA_RULES_DIR=/opt/spinxsca/rules/semgrep \
    SPINXSCA_PROMPTS_DIR=/opt/spinxsca/prompts
EXPOSE 8080
ENTRYPOINT ["node", "/opt/spinxsca/apps/cli/dist/index.mjs"]
CMD ["serve", "--data-dir", "/var/lib/spinxsca", "--host", "0.0.0.0", "--port", "8080"]
