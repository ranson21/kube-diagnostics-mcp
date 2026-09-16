# syntax=docker/dockerfile:1
# Build context is the REPO ROOT (so the Angular app can link ../../rum-client):
#   docker build -f faultlab/proxy/Dockerfile -t faultlab/proxy:dev .
FROM node:22-alpine AS build
WORKDIR /work
# rum-client first (the Angular app depends on it via file:../../rum-client)
COPY rum-client/package.json rum-client/package-lock.json rum-client/tsconfig.json ./rum-client/
COPY rum-client/src ./rum-client/src
RUN cd rum-client && npm ci --no-audit --no-fund && npm run build
WORKDIR /work/faultlab/angular-app
COPY faultlab/angular-app/package.json faultlab/angular-app/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY faultlab/angular-app/ ./
# ~3 MB placeholder hero image (frontend LCP fault) + production build WITH source maps (fault).
RUN node scripts/gen-hero.mjs public/assets/hero-large.png \
 && npx ng build --configuration production --source-map

FROM nginx:1.27-alpine
COPY faultlab/k8s/nginx.conf /etc/nginx/nginx.conf
COPY --from=build /work/faultlab/angular-app/dist/faultlab-app/browser /usr/share/nginx/html
EXPOSE 80
