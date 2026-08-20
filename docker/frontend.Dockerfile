# Frontend image (React/TS/Vite, TDD §27). Dev server for the local lab.
FROM node:20-slim

ENV NODE_ENV=development
WORKDIR /app

# Install deps first for layer caching.
COPY frontend/package.json /app/package.json
# package-lock.json is generated on first `npm install`; copy if present.
RUN npm install

COPY frontend /app

EXPOSE 5173
# Vite binds 127.0.0.1 by config; compose publishes only to 127.0.0.1 (DEP-004).
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
