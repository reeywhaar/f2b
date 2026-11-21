# syntax=docker/dockerfile:1

# Two images from one tree:
#
#   docker build --target engine -t f2b-engine .   fail2ban and its API, beside the host's firewall
#   docker build --target web    -t f2b-web .      the interface and the sign-in
#
# Each stage copies the paths it names and nothing else.

# Built on the machine doing the building rather than under emulation: the bundle is
# architecture-independent, so there is no reason to run npm through QEMU.
FROM --platform=$BUILDPLATFORM node:26-alpine AS bundle
WORKDIR /src
# The lockfile first, on its own layer, so a source edit does not reinstall the world.
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/tsconfig.json web/vite.config.ts web/index.html web/login.html ./
COPY web/public ./public
COPY web/src ./src
RUN npm run build
# An empty bundle is otherwise invisible until somebody loads the page and gets the placeholder.
RUN test -s dist/index.html && test -s dist/login.html

FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
COPY internal ./internal
ARG TARGETOS TARGETARCH VERSION=dev
# CGO off keeps this a static binary, the same one in both images.
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X f2b/internal/app.Version=$VERSION" -o /out/f2b .

# The engine: Alpine's fail2ban, which is what linuxserver/fail2ban runs too, and iptables on the
# nf_tables backend, which is what Docker on a current host writes its own rules with.
FROM alpine:3.22 AS engine
RUN apk add --no-cache fail2ban iptables ip6tables tini
COPY --from=build /out/f2b /usr/local/bin/f2b
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD ["f2b", "healthcheck", "engine"]
# tini reaps what fail2ban's actions leave behind; f2b is not written to be process 1.
ENTRYPOINT ["/sbin/tini", "--", "f2b"]
CMD ["engine"]

# The web: the binary and the bundle. No fail2ban, no Python, no firewall.
FROM alpine:3.22 AS web
COPY --from=build /out/f2b /usr/local/bin/f2b
COPY --from=bundle /src/dist /srv/web
EXPOSE 80
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s CMD ["f2b", "healthcheck", "web"]
ENTRYPOINT ["f2b"]
CMD ["web"]
