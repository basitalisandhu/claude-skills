# Reference multi-stage patterns

Pin tags to a specific version; add `@sha256:<digest>` for production and let a bot update it.

## Python (pip, no compiler at runtime)

```dockerfile
FROM python:3.12-slim AS build
WORKDIR /app
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
COPY requirements.txt .
RUN python -m venv /venv && /venv/bin/pip install -r requirements.txt

FROM python:3.12-slim AS runtime
RUN addgroup --system --gid 10001 app && adduser --system --uid 10001 --ingroup app app \
    && apt-get update && apt-get install -y --no-install-recommends tini \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /venv /venv
COPY --chown=app:app src/ ./src/
ENV PATH="/venv/bin:$PATH" PYTHONUNBUFFERED=1
USER app
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2).status == 200 else 1)"]
ENTRYPOINT ["tini", "--"]
CMD ["python", "-m", "src.main"]
```

## Node.js

```dockerfile
FROM node:22-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build && npm prune --omit=dev && npm cache clean --force

FROM node:22-slim AS runtime
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/dist ./dist
COPY --chown=node:node package.json .
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s CMD ["node", "-e", "fetch('http://127.0.0.1:3000/health').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"]
CMD ["node", "--enable-source-maps", "dist/server.js"]
```

Use `node --init`-free setups with `CMD ["node", ...]` only when the app handles SIGTERM; otherwise add `tini`.

## Go (static binary, scratch or distroless)

```dockerfile
FROM golang:1.23 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/app ./cmd/app

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/app /app
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/app"]
```

Distroless has no shell, so `HEALTHCHECK` must be an exec of the binary itself (add a `--healthcheck` flag) or be left to the orchestrator's probes.

## Java (Temurin JRE)

```dockerfile
FROM eclipse-temurin:21-jdk AS build
WORKDIR /src
COPY . .
RUN ./gradlew --no-daemon bootJar

FROM eclipse-temurin:21-jre
RUN groupadd --system app && useradd --system --gid app --uid 10001 app
WORKDIR /app
COPY --from=build --chown=app:app /src/build/libs/*.jar app.jar
USER app
EXPOSE 8080
HEALTHCHECK CMD ["sh", "-c", "wget -qO- http://127.0.0.1:8080/actuator/health || exit 1"]
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-jar", "app.jar"]
```

## .dockerignore (start here)

```
.git
.gitignore
node_modules
.venv
__pycache__
*.pyc
.env
.env.*
*.log
coverage
dist
build
tests
docs
Dockerfile*
docker-compose*.yml
```

## Build-time secrets

Never `ARG TOKEN` or `ENV TOKEN`. Use BuildKit secrets:

```dockerfile
RUN --mount=type=secret,id=npmrc,target=/root/.npmrc npm ci
```

`docker build --secret id=npmrc,src=$HOME/.npmrc .`
