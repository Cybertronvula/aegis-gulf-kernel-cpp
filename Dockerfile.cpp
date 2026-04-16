# Aegis Gulf Compliance Kernel — C++20 Production Container
# ===========================================================
# Multi-stage build: compile in builder, run in minimal Alpine
#
# Build:
#   docker build -t aegisgulf/kernel-cpp:0.1.0 .
#
# Run:
#   docker run aegisgulf/kernel-cpp:0.1.0 [operation_count]
#
# The resulting image is under 30MB with full AES-256-GCM support.

# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM alpine:3.19 AS builder

RUN apk add --no-cache \
    g++ \
    cmake \
    make \
    openssl-dev \
    openssl-libs-static \
    musl-dev \
    linux-headers

WORKDIR /build

COPY engine.hpp engine.cpp main.cpp CMakeLists.txt ./

RUN cmake -B build \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_EXE_LINKER_FLAGS="-static" \
    && cmake --build build --parallel $(nproc)

# ── Stage 2: Minimal runtime ──────────────────────────────────────────────────
FROM alpine:3.19

LABEL maintainer="Nvula Bontes <aegis-gulf.github.io>"
LABEL description="Aegis Gulf POPIA Compliance Kernel v0.1.0 (C++20)"
LABEL version="0.1.0"

# Non-root user for security
RUN addgroup -S aegis && adduser -S aegis -G aegis

COPY --from=builder /build/build/aegis_benchmark /usr/local/bin/aegis_benchmark

USER aegis

# Default: benchmark 10,000 operations
ENTRYPOINT ["/usr/local/bin/aegis_benchmark"]
CMD ["10000"]
