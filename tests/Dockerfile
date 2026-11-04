# Local validation image only; the deployed observer runs natively under systemd.
ARG DEBIAN_VERSION=12
FROM debian:${DEBIAN_VERSION}-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-apt ansible-core openssl make systemd dbus ca-certificates
WORKDIR /source
CMD ["make", "check"]
