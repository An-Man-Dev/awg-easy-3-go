# syntax=docker/dockerfile:1
ARG AWG_GO_COMMIT=b5928efb6ca19f0153958460c3d141f04abc5c2e
ARG AWG_TOOLS_COMMIT=ee0f0a9aa34ff0a0da4b3433b9512781cfe02843

FROM golang:1.25-alpine AS awg-builder
ARG AWG_GO_COMMIT
RUN apk add --no-cache git ca-certificates
WORKDIR /src
RUN git clone https://github.com/amnezia-vpn/amneziawg-go.git . \
    && git checkout --detach "$AWG_GO_COMMIT" \
    && test "$(git rev-parse HEAD)" = "$AWG_GO_COMMIT"
RUN go mod download && go mod verify \
    && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/amneziawg-go . \
    && cp LICENSE /out/amneziawg-go.LICENSE

FROM alpine:3.20 AS tools-builder
ARG AWG_TOOLS_COMMIT
RUN apk add --no-cache build-base git linux-headers
WORKDIR /src
RUN git clone https://github.com/amnezia-vpn/amneziawg-tools.git . \
    && git checkout --detach "$AWG_TOOLS_COMMIT" \
    && test "$(git rev-parse HEAD)" = "$AWG_TOOLS_COMMIT" \
    && make -C src WITH_SYSTEMDUNITS=no WITH_BASHCOMPLETION=no \
    && mkdir /out && cp src/wg /out/awg && strip /out/awg \
    && cp COPYING /out/amneziawg-tools.COPYING \
    && git archive --format=tar.gz HEAD > /out/amneziawg-tools-source.tar.gz

FROM golang:1.25-alpine AS panel-builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/awg-panel ./cmd/awg-panel \
    && cp /go/pkg/mod/github.com/skip2/go-qrcode@*/LICENSE /out/go-qrcode.LICENSE \
    && cp /usr/local/go/LICENSE /out/Go.LICENSE

FROM alpine:3.20
ARG AWG_GO_COMMIT
ARG AWG_TOOLS_COMMIT
LABEL org.opencontainers.image.title="AWG Panel" \
      org.opencontainers.image.description="Self-hosted AmneziaWG 3 administration" \
      org.opencontainers.image.source="https://github.com/An-Man-Dev/awg-easy-3-go" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.awg-go-revision=$AWG_GO_COMMIT \
      org.opencontainers.image.awg-tools-revision=$AWG_TOOLS_COMMIT
RUN apk add --no-cache ca-certificates iproute2-minimal nftables \
    && mkdir -p /app/web /data /usr/share/licenses/awg-panel /usr/share/awg-panel
WORKDIR /app
COPY --from=awg-builder /out/amneziawg-go /usr/local/bin/amneziawg-go
COPY --from=tools-builder /out/awg /usr/local/bin/awg
COPY --from=panel-builder /out/awg-panel ./awg-panel
COPY --from=awg-builder /out/amneziawg-go.LICENSE /usr/share/licenses/awg-panel/
COPY --from=tools-builder /out/amneziawg-tools.COPYING /usr/share/licenses/awg-panel/
COPY --from=tools-builder /out/amneziawg-tools-source.tar.gz /usr/share/awg-panel/
COPY --from=panel-builder /out/go-qrcode.LICENSE /usr/share/licenses/awg-panel/
COPY --from=panel-builder /out/Go.LICENSE /usr/share/licenses/awg-panel/
COPY THIRD_PARTY_NOTICES.md /usr/share/licenses/awg-panel/
COPY LICENSE /usr/share/licenses/awg-panel/LICENSE
ENV AWG_DATA_DIR=/data AWG_WEB_DIR=/app/web GOMEMLIMIT=20MiB GOGC=100
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 CMD ["./awg-panel", "--healthcheck"]
ENTRYPOINT ["./awg-panel"]
