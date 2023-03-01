ARG BASE_IMAGE=docker.io/library/ubuntu
ARG BASE_TAG=kinetic

# ----------------------------------------
# Hoppr-cop install stage
# ----------------------------------------
FROM $BASE_IMAGE:$BASE_TAG AS builder
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG APT_PKGS="curl python3 python3-apt python3-pip ruby-full"

# renovate: datasource=github-releases depName=anchore/grype/ versioning=semver
ARG GRYPE_VERSION="v0.56.0"

# renovate: datasource=github-releases depName=aquasecurity/trivy/ versioning=semver
ARG TRIVY_VERSION="v0.31.3"

COPY dist/hoppr_cop-*-py3-none-any.whl /tmp

# hadolint ignore=DL3008
RUN apt-get update \
  && apt-get install --yes --no-install-recommends ${APT_PKGS} \
  && apt-get clean \
  && rm -r /var/lib/apt/lists/* \
  && export PIP_TRUSTED_HOST="pypi.org pypi.python.org files.pythonhosted.org" \
  && python3 -m pip install --no-cache-dir /tmp/hoppr_cop-*-py3-none-any.whl \
  && rm /tmp/hoppr_cop-*-py3-none-any.whl \
  && curl -sSfL https://raw.githubusercontent.com/anchore/grype/$GRYPE_VERSION/install.sh | sh -s -- -b /usr/local/bin $GRYPE_VERSION \
  && curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/$TRIVY_VERSION/contrib/install.sh | sh -s -- -b /usr/local/bin $TRIVY_VERSION \
  && apt-get autoremove --yes curl


# ----------------------------------------
# Final stage
# ----------------------------------------
FROM $BASE_IMAGE:$BASE_TAG

# Flatten build layers into single layer
COPY --from=builder / /
ENV XDG_CACHE_HOME=/cache
ENV CACHE_DIR=/cache
VOLUME /cache
VOLUME /hoppr
WORKDIR /hoppr
ENTRYPOINT ["/usr/local/bin/hoppr-cop"]
