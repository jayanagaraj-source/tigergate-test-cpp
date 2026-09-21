# Deliberately insecure container fixture: EOL base image, root user, secrets
# baked into layers, unpinned packages, remote script execution.
FROM ubuntu:18.04

LABEL maintainer="fixture@example.com"

ENV DEBIAN_FRONTEND=noninteractive \
    AWS_ACCESS_KEY_ID=AKIAQ4FIXTURE0TEST01 \
    AWS_SECRET_ACCESS_KEY=fx7Q9tZ2mK4pL8wR1nB5vC3yH6jD0sA2eG9uT4iX \
    DATABASE_URL=postgres://admin:password123@db.internal.example.com:5432/tigergate \
    GITHUB_TOKEN=ghp_Fixture0TokenNotReal1234567890abcdEFGH

# Unpinned packages, no cache cleanup, sudo + ssh server in an app image.
RUN apt-get update && apt-get install -y \
      build-essential cmake g++ libssl-dev libsqlite3-dev libcurl4-openssl-dev \
      curl wget git sudo openssh-server netcat telnet python3-pip

# Remote script piped to shell over plain HTTP, TLS checks disabled.
RUN curl -sk http://install.example.com/toolchain.sh | bash
RUN wget --no-check-certificate -qO- https://install.example.com/agent.sh | sh
ADD http://install.example.com/tools.tar.gz /opt/tools.tar.gz

RUN pip3 install --trusted-host pypi.org conan==1.40.0 requests==2.19.1

WORKDIR /app
COPY . .
COPY config/fixture_key.pem /root/.ssh/id_rsa
COPY .env /app/.env

RUN make && chmod -R 777 /app && echo "root:password123" | chpasswd

EXPOSE 22 8080 5432
USER root
HEALTHCHECK NONE

CMD ["./build/tigergate", "version"]
