# syntax=docker/dockerfile:1

# Opengrep is a pinned release, checked against its published checksum when the image is built (ADR 0027, 0036).
FROM scratch AS opengrep-amd64
ADD --chmod=755 --checksum=sha256:a66aa3278457f02b287b985a45b6762aebcaba5000f2689245fd1ed86d1456c7 \
  https://github.com/opengrep/opengrep/releases/download/v1.30.2/opengrep_manylinux_x86 /opengrep
FROM scratch AS opengrep-arm64
ADD --chmod=755 --checksum=sha256:90acea5df4b733083f388d4feeb250ca802f671b33d1f222653d1e571dd2b0d8 \
  https://github.com/opengrep/opengrep/releases/download/v1.30.2/opengrep_manylinux_aarch64 /opengrep
FROM opengrep-${TARGETARCH} AS opengrep

# git clones the code: Debian slim with git rather than distroless. The agent has no runtime dependencies: Node runs
# the TypeScript sources directly.
FROM node:26.12.1-trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
  && rm -rf /var/lib/apt/lists/* /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx /opt/yarn* /usr/local/bin/yarn* \
  && mkdir -p /data /scan && chown node:node /data /scan
COPY --from=opengrep /opengrep /usr/local/bin/opengrep
WORKDIR /app
COPY package.json ./
COPY agent ./agent
COPY rules ./rules
# The agent's secret lives sealed in /data. Clones go to /scan, which compose mounts as a tmpfs, and are deleted after
# each scan.
ENV NODE_ENV=production PORT=9100 SAST_AGENT_STATE=/data/agent.state WORK_DIR=/scan TMPDIR=/scan
VOLUME /data
EXPOSE 9100
USER node
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD ["node", "-e", "fetch('http://127.0.0.1:9100/healthz').then(r => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]
CMD ["node", "agent/main.ts"]
