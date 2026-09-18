# Use Ubuntu 22.04
FROM ubuntu:22.04

ARG SURI_VERSION=7.0.2

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# 1. Install dependencies
# Added: python3-yaml (Fixes the build error), liblzma-dev, and libssl-dev
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    curl \
    tar \
    python3 \
    python3-pip \
    python3-yaml \
    libpcre2-dev \
    libpcap-dev \
    libnet1-dev \
    libyaml-dev \
    zlib1g-dev \
    libcap-ng-dev \
    libmagic-dev \
    libjansson-dev \
    libevent-dev \
    liblua5.1-dev \
    liblzma-dev \
    libssl-dev \
    rustc \
    cargo \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# 2. Download and extract Suricata
WORKDIR /src
RUN curl -L https://www.openinfosecfoundation.org/download/suricata-${SURI_VERSION}.tar.gz | tar xz

WORKDIR /src/suricata-${SURI_VERSION}

# 3. Configure and Build
# Added --enable-python to ensure python tools are integrated correctly
RUN ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var \
    --enable-profiling \
    --enable-lua \
    --enable-python \
    && make -j $(nproc) \
    && make install \
    && make install-full \
    && ldconfig

# 4. Setup log directory
RUN mkdir -p /var/log/suricata

ENTRYPOINT ["suricata"]