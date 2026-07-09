# Minimal egress-allowlist forward proxy (tinyproxy on Alpine). Built in-repo
# rather than pulling a third-party proxy image: the config is the security
# control, so it must be auditable and pinned alongside the code that relies on
# it. The image carries no application secrets and publishes no port.
FROM alpine:3.21

RUN apk add --no-cache tinyproxy

COPY tinyproxy.conf /etc/tinyproxy/tinyproxy.conf
COPY filter /etc/tinyproxy/filter

# Drop to an unprivileged user; tinyproxy's own User/Group directives are
# omitted so it does not try to setuid (which no-new-privileges would block).
USER nobody:nobody

EXPOSE 8888

# -d keeps tinyproxy in the foreground so it is the container's PID 1 workload.
ENTRYPOINT ["tinyproxy", "-d", "-c", "/etc/tinyproxy/tinyproxy.conf"]
