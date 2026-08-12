# syntax=docker/dockerfile:1.7

# Pin the complete multi-platform builder manifest. The official Alpine Rust image
# builds for the native musl target, producing a static controller for both amd64 and
# arm64. The builder never enters the shipped image.
FROM docker.io/library/rust:1.92.0-alpine3.23@sha256:f6c22e0a256c05d44fca23bf530120b5d4a6249a393734884281ca80782329bc AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --locked --profile controller -p thorax-kubernetes-controller \
    && ! readelf -l target/controller/thorax-kubernetes-controller | grep -q INTERP \
    && ! readelf -d target/controller/thorax-kubernetes-controller | grep -q NEEDED \
    && cp target/controller/thorax-kubernetes-controller /thorax-kubernetes-controller

# A static binary needs no OS, libc, shell, package database, or certificate bundle.
# The Kubernetes client uses the explicitly mounted service-account CA.
FROM scratch
ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="Thorax Kubernetes controller" \
      org.opencontainers.image.description="Namespaced Thorax vault-to-Kubernetes Secret trust terminator" \
      org.opencontainers.image.source="https://github.com/backbone-hq/thorax" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"
COPY --from=builder --chown=65532:65532 /thorax-kubernetes-controller /thorax-kubernetes-controller
USER 65532:65532
ENTRYPOINT ["/thorax-kubernetes-controller"]
