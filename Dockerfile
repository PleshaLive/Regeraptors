# syntax=docker/dockerfile:1
FROM node:20-slim AS base

WORKDIR /app

COPY package*.json ./
RUN npm install --production && npm cache clean --force

COPY . .

ENV NODE_ENV=production
ENV PORT=3000
EXPOSE 3000

CMD ["node", "src/server.js"]
