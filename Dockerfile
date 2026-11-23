# syntax=docker/dockerfile:1
# Base image pinned by digest. To refresh:
#   docker buildx imagetools inspect alpine:3.24 --format '{{json .Manifest.Digest}}'
# then update tag + digest below (Dependabot also proposes updates).
FROM alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

LABEL org.opencontainers.image.title="entra-config-backup" \
      org.opencontainers.image.description="Nightly read-only backup of Entra Conditional Access to git" \
      org.opencontainers.image.source="https://github.com/davidlahoz/entra-config-backup" \
      org.opencontainers.image.licenses="MIT"

# Package versions float within the digest-pinned Alpine release (apk does not keep old versions).
# hadolint ignore=DL3018
RUN apk add --no-cache bash curl jq openssl git openssh-client ca-certificates coreutils \
 && addgroup -g 10001 ca-backup \
 && adduser -D -H -u 10001 -G ca-backup -s /sbin/nologin ca-backup

# GitHub SSH host keys, verified against https://api.github.com/meta (see README).
COPY docker/ssh_known_hosts /etc/ssh/ssh_known_hosts
RUN printf 'Host *\n  StrictHostKeyChecking yes\n  UserKnownHostsFile /dev/null\n' >> /etc/ssh/ssh_config

COPY --chmod=0755 src/ca-backup.sh /usr/local/bin/ca-backup

USER 10001:10001
ENV HOME=/tmp LC_ALL=C
ENTRYPOINT ["/usr/local/bin/ca-backup"]
