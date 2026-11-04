# Analysis toolbox for the agent's sandboxed shell (ADR-043).
# Build once with network access, then pin the resulting image id in operator configuration:
#   pnpm toolbox:build            # prints the pinned reference and the config line
#   ai:
#     autonomy:
#       toolbox_image: "sha256:<id printed by the build>"
# At run time the container has no network, a read-only root filesystem and runs as an
# unprivileged user; nothing in this image is ever executed against the real repository.
FROM node:22-alpine@sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914

RUN apk add --no-cache ripgrep jq git python3 bash coreutils findutils grep sed gawk file \
 && npm install -g --omit=dev @ast-grep/cli@0.39.5 \
 && npm cache clean --force \
 # No package managers at run time: the network is off anyway, this removes the temptation.
 && rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx /sbin/apk /etc/apk /lib/apk \
 && addgroup -S analyst && adduser -S -G analyst -h /tmp analyst

USER analyst
WORKDIR /src
ENTRYPOINT []
CMD ["sh"]
