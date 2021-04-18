# This Dockerfile creates an image with a release build of the broker.
#
# To run a container:
#
#   docker run --rm -v $(pwd):/data:ro portier/broker /data/config.toml
#
# To use your own data files (helpful in a production deployment):
#
#   tar zvcf data.tar.gz --exclude='*.po' lang res tmpl
#   [copy data.tar.gz up to an HTTP server]
#   docker build -t portier/broker:latest --build-arg=data=url --build-arg=data_url=https://example.com/data.tar.gz .
#   docker run --rm -e ... portier/broker
#

# trick shamelessly stolen from https://stackoverflow.com/a/54245466
ARG data=default

# Create a release build.
FROM rust:1-slim-buster AS build
SHELL ["/bin/sh", "-x", "-c"]
RUN apt-get update \
  && apt-get -y --option=Dpkg::options::=--force-unsafe-io upgrade --no-install-recommends \
  && apt-get -y --option=Dpkg::options::=--force-unsafe-io install --no-install-recommends \
    libssl-dev \
    pkg-config \
  && apt-get clean \
  && find /var/lib/apt/lists -type f -delete
WORKDIR /src
COPY . .
RUN cargo build --release
RUN tar zcf /data.tar.gz --exclude='*.po' lang res tmpl

# Prepare a final image from a plain Debian base.
FROM debian:buster-slim AS data_default
ONBUILD COPY --from=build /data.tar.gz /

FROM debian:buster-slim AS data_url
ONBUILD ARG data_url
ONBUILD ADD ${data_url} /data.tar.gz

FROM data_${data}

SHELL ["/bin/sh", "-x", "-c"]

# Add a user and group first to make sure their IDs get assigned consistently,
# regardless of whatever dependencies get added.
RUN groupadd -r -g 999 portier-broker \
  && useradd -r -g portier-broker -u 999 portier-broker

# Install run-time dependencies.
RUN apt-get update \
  && apt-get -y --option=Dpkg::options::=--force-unsafe-io upgrade --no-install-recommends \
  && apt-get -y --option=Dpkg::options::=--force-unsafe-io install --no-install-recommends \
    ca-certificates \
  && apt-get clean \
  && find /var/lib/apt/lists -type f -delete

# Copy in the 'package' directory from the build image.
RUN mkdir -p /opt/portier-broker && tar -C /opt/portier-broker -xf /data.tar.gz && rm /data.tar.gz
COPY --from=build /src/target/release/portier-broker /opt/portier-broker
WORKDIR /opt/portier-broker

# Set image settings.
ENTRYPOINT ["/opt/portier-broker/portier-broker"]
USER portier-broker
ENV BROKER_LISTEN_IP=::
EXPOSE 3333
