FROM aquasec/trivy:0.75.0@sha256:af6acf9a6b85dfe389a1941505c0ce9efef52a4719635e1a962f022a3d855daa AS trivy
FROM ghcr.io/astral-sh/uv:0.13.1@sha256:4a1f3666816dafadd20ceb71eac9a7d56d7ef30279f7d64048519ab901ada336 AS uv

FROM python:3.15.0-slim@sha256:2da676046630d7bf14c6764ae1143dc7fa0377a53f94bf5a642f0b214aca5bce AS build
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --locked --no-dev --no-editable

FROM python:3.15.0-slim@sha256:2da676046630d7bf14c6764ae1143dc7fa0377a53f94bf5a642f0b214aca5bce
ARG TARGETARCH
# renovate: datasource=github-releases depName=cli/cli
ARG GH_VERSION=2.103.3
ARG GH_SHA256_AMD64=bb766f710eef8ede859c18578c72c327597cd4c8a85b06001b1f3843c6019386
ARG GH_SHA256_ARM64=7862c86c72f43df3a2d93ddde6f473285b4e2af61b494849846827e513ef6484
# renovate: datasource=github-releases depName=CycloneDX/cyclonedx-cli
ARG CYCLONEDX_VERSION=0.33.1
ARG CYCLONEDX_SHA256_AMD64=bfc8b2538da86fe239bc53658bbb63c1c8c510a293c1e6891aa5bea5d3c58746
ARG CYCLONEDX_SHA256_ARM64=b2e9fdf9665ef49868a2ec012171c6e785dcd69745bc5869e53e4f4bfb096a5f
ENV DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1
RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) gh_sha="${GH_SHA256_AMD64}"; cyclonedx_arch=x64; cyclonedx_sha="${CYCLONEDX_SHA256_AMD64}" ;; \
      arm64) gh_sha="${GH_SHA256_ARM64}"; cyclonedx_arch=arm64; cyclonedx_sha="${CYCLONEDX_SHA256_ARM64}" ;; \
      *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    apt-get update; \
    apt-get install --no-install-recommends -y ca-certificates curl; \
    gh_archive="gh_${GH_VERSION}_linux_${TARGETARCH}.tar.gz"; \
    curl -fsSL -o "/tmp/${gh_archive}" "https://github.com/cli/cli/releases/download/v${GH_VERSION}/${gh_archive}"; \
    echo "${gh_sha}  /tmp/${gh_archive}" | sha256sum -c -; \
    tar -xz --strip-components=2 -C /usr/local/bin -f "/tmp/${gh_archive}" "gh_${GH_VERSION}_linux_${TARGETARCH}/bin/gh"; \
    curl -fsSL -o /usr/local/bin/cyclonedx "https://github.com/CycloneDX/cyclonedx-cli/releases/download/v${CYCLONEDX_VERSION}/cyclonedx-linux-${cyclonedx_arch}"; \
    echo "${cyclonedx_sha}  /usr/local/bin/cyclonedx" | sha256sum -c -; \
    chmod +x /usr/local/bin/cyclonedx; \
    rm "/tmp/${gh_archive}"; \
    apt-get purge -y curl; \
    apt-get autoremove -y; \
    rm -rf /var/lib/apt/lists/*
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=build /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:${PATH}"
RUN useradd --create-home tool
USER tool
ENTRYPOINT ["depgraph-gap"]
