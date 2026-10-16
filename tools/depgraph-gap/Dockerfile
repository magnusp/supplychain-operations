FROM aquasec/trivy:0.75.0 AS trivy
FROM ghcr.io/astral-sh/uv:0.13.1 AS uv

FROM python:3.13.16-slim AS build
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --locked --no-dev --no-editable

FROM python:3.13.16-slim
ARG TARGETARCH
# renovate: datasource=github-releases depName=cli/cli
ARG GH_VERSION=2.102.0
# renovate: datasource=github-releases depName=CycloneDX/cyclonedx-cli
ARG CYCLONEDX_VERSION=0.33.1
ENV DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1
RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates curl \
    && curl -fsSL "https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_linux_${TARGETARCH}.tar.gz" \
        | tar -xz --strip-components=2 -C /usr/local/bin "gh_${GH_VERSION}_linux_${TARGETARCH}/bin/gh" \
    && CYCLONEDX_ARCH="$(echo "${TARGETARCH}" | sed s/amd64/x64/)" \
    && curl -fsSL -o /usr/local/bin/cyclonedx \
        "https://github.com/CycloneDX/cyclonedx-cli/releases/download/v${CYCLONEDX_VERSION}/cyclonedx-linux-${CYCLONEDX_ARCH}" \
    && chmod +x /usr/local/bin/cyclonedx \
    && apt-get purge -y curl \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=build /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:${PATH}"
RUN useradd --create-home tool
USER tool
ENTRYPOINT ["depgraph-gap"]
