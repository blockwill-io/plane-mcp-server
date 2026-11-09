# Base images are pinned by digest so a rebuild cannot silently pick up a
# different image. To update: docker buildx imagetools inspect <image:tag>
FROM python:3.11-slim@sha256:07d4824036af339fa1b6ef769cc99d9c10a141769538b52b3b597c84f7a7b535

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# uv, same version as mise.toml
COPY --from=ghcr.io/astral-sh/uv:0.9.18@sha256:5713fa8217f92b80223bc83aac7db36ec80a84437dbc0d04bbc659cae030d8c9 /uv /usr/local/bin/uv

# Install exactly what uv.lock pins (--locked also fails if it is out of date
# with pyproject.toml),
# into /app/.venv with the image's own Python.
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_NO_CACHE=1
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --locked --no-dev --no-install-project
COPY plane_mcp/ ./plane_mcp/
RUN uv sync --locked --no-dev --no-editable
ENV PATH="/app/.venv/bin:$PATH"

# Run unprivileged. The code and venv stay root-owned, so the process cannot
# rewrite them. TOKEN_STORE_DIR (an Azure Files mount in production) must be
# writable by this uid: SMB mounts default to 0777, otherwise mount it with
# uid=10001,gid=10001.
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin app
USER 10001

# Expose port for HTTP transports (SSE, streamable-http, http)
EXPOSE 8211

# Set environment variables with defaults
ENV FASTMCP_PORT=8211

# Default to streamable-http transport, but allow override via command
# Users can override by passing different transport as CMD
ENTRYPOINT ["python", "-m", "plane_mcp"]
CMD ["http"]
