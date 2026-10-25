# Forum DSI kiosk — production image
FROM node:22-alpine

WORKDIR /app

# Install only production deps (uses the lockfile when present)
COPY package*.json ./
RUN npm install --omit=dev && npm cache clean --force

# App code
COPY server ./server
COPY public ./public

ENV NODE_ENV=production \
    PORT=8080 \
    HOST=0.0.0.0

EXPOSE 8080

# Basic container healthcheck (the kiosk responds even if ES is down)
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+ (process.env.PORT||8080) +'/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

USER node

CMD ["node", "server/server.mjs"]
