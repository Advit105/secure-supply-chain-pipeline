# Pinned older base on purpose so Trivy has real OS CVEs to find in the demo.
# For a heavier target, replace this whole file with:  FROM bkimminich/juice-shop
FROM node:18.19.0-bullseye-slim

WORKDIR /app

# non-root: Kyverno/Checkov best-practice, and it's one line.
RUN useradd --create-home --shell /usr/sbin/nologin appuser

COPY package.json ./
RUN npm install --omit=dev && npm cache clean --force

COPY server.js ./

USER appuser
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s CMD node -e "require('http').get('http://127.0.0.1:3000/health',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"
CMD ["node", "server.js"]
