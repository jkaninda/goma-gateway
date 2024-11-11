FROM golang:1.23.3 AS build
WORKDIR /app
ARG appVersion=""
ARG buildTime=""
ARG gitCommit=""
# Copy the source code.
COPY . .
# Installs Go dependencies
RUN go mod download

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-X 'github.com/jkaninda/goma-gateway/util.Version=${appVersion}' -X 'github.com/jkaninda/goma-gateway/util.buildTime=${buildTime}'-X 'github.com/jkaninda/goma-gateway/util.gitCommit=${gitCommit}'" -o /app/goma

FROM alpine:3.20.3
ENV TZ=UTC
ARG WORKDIR="/etc/goma/"
ARG appVersion=""
ARG user="goma"
LABEL author="Jonas Kaninda"
LABEL version=${appVersion}
LABEL github="github.com/jkaninda/goma-gateway"

RUN mkdir -p ${WORKDIR} && \
     chmod a+rw ${WORKDIR}
COPY --from=build /app/goma /usr/local/bin/goma
RUN chmod a+x /usr/local/bin/goma && \
    ln -s /usr/local/bin/goma /usr/bin/goma
RUN addgroup -S ${user} && adduser -S ${user} -G ${user}
RUN apk --update add --no-cache tzdata ca-certificates curl #libcap && setcap 'cap_net_bind_service=+ep' /usr/local/bin/goma
USER ${user}
EXPOSE 8080 8443
WORKDIR $WORKDIR
ENTRYPOINT ["/usr/local/bin/goma"]