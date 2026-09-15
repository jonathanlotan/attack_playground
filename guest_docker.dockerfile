# pinned - see docker-compose.yaml for why "latest" is avoided
FROM containerssh/agent:v0.10.0 AS agent-binary

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && apt install -y \
    bash \
    coreutils \
    iputils-ping \
    netcat-openbsd \
    iproute2 \
    python2 \
    python3 \
    python3-pip \
    gcc \
    g++ \
    make \
    git \
    vim \
    nano \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Create the user (with bash as shell)
RUN useradd -m guestuser

# Copy the agent binary from the official image
COPY --from=agent-binary /usr/bin/containerssh-agent /usr/bin/containerssh-agent

USER guestuser
WORKDIR /home/guestuser

CMD ["console", "--", "/bin/bash"]
