FROM node:22.11.0-alpine3.20
WORKDIR /app
COPY --chown=node:node . .
RUN npm ci --omit=dev
USER node
HEALTHCHECK --interval=30s CMD wget -qO- http://127.0.0.1:3000/health || exit 1
EXPOSE 3000
CMD ["node", "server.js"]
