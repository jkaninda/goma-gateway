########################
# Builder Stage
########################
FROM golang:1.25.1 AS build

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
FROM alpine:3.22.2

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


# Install runtime dependencies and set up directories
RUN apk --update --no-cache add tzdata ca-certificates curl && \
    mkdir -p "$CONFIG_DIR" "$EXTRADIR" "$CERTS_DIR" && \
    chmod a+rw "$CONFIG_DIR" "$EXTRADIR" "$CERTS_DIR"

# Copy built binary
COPY --from=build /app/goma /usr/local/bin/goma
RUN chmod a+x /usr/local/bin/goma && ln -s /usr/local/bin/goma /goma

# Expose HTTP and HTTPS ports
EXPOSE 8080 8443

ENTRYPOINT ["/goma"]
