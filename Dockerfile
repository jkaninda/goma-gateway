########################
# Builder Stage
########################
FROM golang:1.27.0 AS build

WORKDIR /app

ARG appVersion=""
ARG buildTime=""
ARG gitCommit=""

# Copy source code
COPY . .

# Download Go dependencies
RUN go mod download

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w \
    -X 'github.com/jkaninda/goma-gateway/internal/version.Version=${appVersion}' \
    -X 'github.com/jkaninda/goma-gateway/internal/version.buildTime=${buildTime}' \
    -X 'github.com/jkaninda/goma-gateway/internal/version.gitCommit=${gitCommit}'" \
    -o /app/goma

########################
# Final Stage
########################
FROM alpine:3.24.1

ENV TZ=UTC

# Define working directories
ARG CONFIG_DIR="/etc/goma"
ARG EXTRADIR="${CONFIG_DIR}/extra"
ARG CERTS_DIR="/etc/letsencrypt"

# Metadata labels
ARG appVersion=""
ARG appVersion=""
ARG buildTime=""
ARG gitCommit=""
LABEL org.opencontainers.image.title="goma-gateway" \
      org.opencontainers.image.description="Simple Lightweight High-Performance Declarative API Gateway Management" \
      org.opencontainers.image.licenses="Apache" \
      org.opencontainers.image.authors="Jonas Kaninda" \
      org.opencontainers.image.version="${appVersion}" \
      org.opencontainers.image.source="https://github.com/jkaninda/goma-gateway" \
      org.opencontainers.image.revision="${gitCommit}" \
      org.opencontainers.image.created="${buildTime}"


# Install runtime dependencies and set up directories.
RUN apk --update --no-cache add tzdata ca-certificates curl && \
    addgroup -g 10001 -S goma && \
    adduser -u 10001 -S -G goma -h /home/goma goma && \
    mkdir -p "$CONFIG_DIR" "$EXTRADIR" "$CERTS_DIR" && \
    chown -R goma:goma "$CONFIG_DIR" "$EXTRADIR" "$CERTS_DIR" && \
    chmod 0750 "$CONFIG_DIR" "$EXTRADIR" && \
    chmod 0700 "$CERTS_DIR"

# Copy built binary
COPY --from=build /app/goma /usr/local/bin/goma
RUN chmod 0755 /usr/local/bin/goma && ln -s /usr/local/bin/goma /goma


EXPOSE 8080 8443

ENTRYPOINT ["/goma"]
