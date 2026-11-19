# The XDRCheck container image: the prebuilt Linux tools and the corpus release archive of one version, nothing
# built inside. `scripts/dist.sh image` (`make dist-image`) builds it from dist/ with the network off and
# smoke-tests it; docs/release.md section 10 describes it.
#
# Build context: the corpus archive xdrcheck-<VERSION>.tar.gz, the binaries
# xdrcheck-<VERSION>-linux-<TARGETARCH>.tar.gz and a SHA256SUMS listing both.
#
# The base is pinned by digest (the multi-platform index of debian trixie-slim), so a rebuild never picks up a
# different base silently.
ARG BASE=debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

FROM ${BASE} AS unpack
ARG VERSION
ARG TARGETARCH
WORKDIR /in
COPY SHA256SUMS xdrcheck-${VERSION}.tar.gz xdrcheck-${VERSION}-linux-${TARGETARCH}.tar.gz ./
# Both archives must match the release's checksums before anything is unpacked.
RUN sha256sum --check --strict SHA256SUMS \
 && mkdir -p /out/xdrcheck \
 && tar --no-same-owner -xzf xdrcheck-${VERSION}.tar.gz -C /out/xdrcheck --strip-components=1 \
 && tar --no-same-owner -xzf xdrcheck-${VERSION}-linux-${TARGETARCH}.tar.gz -C /out/xdrcheck --strip-components=1 \
 && (cd /out/xdrcheck && sha256sum --check --strict --quiet SHA256SUMS) \
 && test -x /out/xdrcheck/bin/xdrcheck && test -x /out/xdrcheck/bin/xdrcheck-corpus && test -x /out/xdrcheck/bin/xdrlint

FROM ${BASE}
ARG VERSION
ARG REVISION
LABEL org.opencontainers.image.title="xdrcheck" \
      org.opencontainers.image.description="XDRCheck: the Stellar XDR corpus and its tools (xdrcheck, xdrcheck-corpus, xdrlint)" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.source="https://github.com/tolgayayci/xdrcheck" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=unpack /out/xdrcheck /opt/xdrcheck
RUN useradd --system --uid 10001 --home-dir /work --create-home xdrcheck
ENV PATH=/opt/xdrcheck/bin:$PATH
# The release's layout: corpus/ and stress/ beside pins.toml, so `--corpus corpus` (the tools' default) works here.
WORKDIR /opt/xdrcheck
USER xdrcheck
