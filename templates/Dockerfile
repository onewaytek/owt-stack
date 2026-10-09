# syntax=docker/dockerfile:1.7
#
# The image every owt-stack app builds. Copy it into the app's repository and set
# the three ARGs below (or pass them with --build-arg). Every stage starts from a Red
# Hat Hummingbird image: minimal, rebuilt as fixes land, pulled from
# registry.access.redhat.com without a login. Three stages:
#
# 1. css: Tailwind scans templates/ (and Rust sources, if the app's input CSS says
#    so) and emits the stylesheet. npm, not the standalone binary, so plugins such as
#    Flowbite load. Node is build-time only.
# 2. build: cargo-chef caches the dependency graph in its own layer, so a source edit
#    recompiles the app and nothing else. SQLX_OFFLINE: queries are checked against
#    the committed .sqlx/ data; no database at build time. Migrations and Askama
#    templates are compiled into the binary.
# 3. runtime: Hummingbird's glibc base, the same glibc the build stage links against.
#    rustls means no OpenSSL; the image carries CA certificates for outbound TLS. It
#    keeps bash and coreutils, so operations can `oc exec` shell tools such as `sh`,
#    `timeout` and `env` into the pod; the build fails if they go missing.
#
# The images follow a major version (rust:1, nodejs:22, core-runtime:2), so a rebuild
# picks up their fixes. rust and core-runtime are cut from the same Hummingbird
# release, so the binary's glibc matches the runtime's.
#
# Copy templates/dockerignore beside it as .dockerignore: both `COPY . .` steps take
# the whole build context.
#
# Built on GitHub-hosted runners and pushed to ghcr; the cluster pulls it through an
# ImageStream (see templates/openshift/app.yaml). The ARC runners are rootless with no
# Docker daemon, so they run checks, never this.

# The binary's name (the Cargo package's `[[bin]]`, usually the package name).
ARG BIN=app
# The port the binary binds (its BIND_ADDR default inside the image).
ARG PORT=8000
# npm script that writes the stylesheet into static/.
ARG CSS_SCRIPT=css:build

FROM registry.access.redhat.com/hi/nodejs:22 AS css
ARG CSS_SCRIPT
WORKDIR /app
# The image runs as uid 65532, and npm writes node_modules/ and the stylesheet among
# the copied files.
COPY --chown=65532:0 package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY --chown=65532:0 . .
RUN npm run ${CSS_SCRIPT}

FROM registry.access.redhat.com/hi/rust:1 AS chef
# Hummingbird publishes no cargo-chef image. Pinned; cached as its own layer.
RUN cargo install cargo-chef --version 0.1.78 --locked
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS build
ARG BIN
COPY --from=planner /app/recipe.json recipe.json
# owt-stack is a public git dependency: no token, no secret mount. --locked: the
# lockfile's pins, or the build fails.
RUN cargo chef cook --release --locked --recipe-path recipe.json
COPY . .
ENV SQLX_OFFLINE=true
RUN cargo build --release --locked --bin ${BIN} && cp target/release/${BIN} /app/server

FROM registry.access.redhat.com/hi/core-runtime:2
ARG PORT
ARG VERSION=dev
# Runs the shell tools operations rely on, rather than looking them up: a base image
# that drops one fails the build, not an incident.
RUN timeout 5 env >/dev/null
LABEL org.opencontainers.image.version=$VERSION
WORKDIR /app
COPY --from=build /app/server /usr/local/bin/server
COPY --from=css /app/static ./static
ENV BIND_ADDR=0.0.0.0:${PORT}
EXPOSE ${PORT}
# core-runtime's non-root user; /etc/passwd has no name for it.
USER 65532
ENTRYPOINT ["/usr/local/bin/server"]
