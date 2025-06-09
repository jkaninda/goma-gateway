FROM golang:1.24.4 AS build
WORKDIR /app
ARG appVersion=""
ARG buildTime=""
ARG gitCommit=""
# Copy the source code.
COPY . .
# Installs Go dependencies
RUN go mod download

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-X 'github.com/jkaninda/goma-gateway/internal/version.Version=${appVersion}' -X 'github.com/jkaninda/goma-gateway/internal/version.buildTime=${buildTime}'-X 'github.com/jkaninda/goma-gateway/internal/version.gitCommit=${gitCommit}'" -o /app/goma

FROM alpine:3.22.0
ENV TZ=UTC
ARG WORKDIR="/etc/goma"
ARG EXTRADIR="${WORKDIR}/extra"
ARG appVersion=""
LABEL org.opencontainers.image.title="goma-gateway"
LABEL org.opencontainers.image.description="Simple Lightweight High-Performance Declarative API Gateway Management"
LABEL org.opencontainers.image.licenses="Apache"
LABEL org.opencontainers.image.authors="Jonas Kaninda <me@jkaninda.dev>"
LABEL org.opencontainers.image.version=${appVersion}
LABEL org.opencontainers.image.source="github.com/jkaninda/goma-gateway"

RUN mkdir -p ${WORKDIR} ${EXTRADIR} && \
     chmod a+rw ${WORKDIR} ${EXTRADIR}
COPY --from=build /app/goma /usr/local/bin/goma
RUN chmod a+x /usr/local/bin/goma
RUN apk --update add --no-cache tzdata ca-certificates curl
EXPOSE 8080 8443
WORKDIR $WORKDIR
ENTRYPOINT ["/usr/local/bin/goma"]