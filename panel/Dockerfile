# Build from panel/: docker build -t pisentry-panel .
FROM --platform=$BUILDPLATFORM node:22-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a AS ui
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web ./
RUN npm run build

FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build
ARG TARGETOS TARGETARCH TARGETVARIANT
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY --from=ui /src/internal/web/dist ./internal/web/dist
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GOARM=${TARGETVARIANT#v} \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/pisentry-panel ./cmd/pisentry-panel

FROM gcr.io/distroless/static-debian12:latest@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2
LABEL org.opencontainers.image.source="https://github.com/pisentry/pisentry" \
      org.opencontainers.image.description="Fleet panel for pisentry agents" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /out/pisentry-panel /usr/local/bin/pisentry-panel
USER 65532:65532
VOLUME /data
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/pisentry-panel"]
# Plain HTTP is refused off loopback: mount a certificate and key into /tls.
CMD ["serve", "-data", "/data", "-listen", ":8443", "-tls-cert", "/tls/cert.pem", "-tls-key", "/tls/key.pem"]
