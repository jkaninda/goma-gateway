FROM golang:1.23.5 AS build
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

FROM alpine:3.21.2
ENV TZ=UTC
ARG WORKDIR="/etc/goma"
ARG EXTRADIR="${WORKDIR}/extra"
ARG appVersion=""
LABEL author="Jonas Kaninda"
LABEL version=${appVersion}
LABEL github="github.com/jkaninda/goma-gateway"

RUN mkdir -p ${WORKDIR} ${EXTRADIR} && \
     chmod a+rw ${WORKDIR} ${EXTRADIR}
COPY --from=build /app/goma /usr/local/bin/goma
RUN chmod a+x /usr/local/bin/goma
RUN apk --update add --no-cache tzdata ca-certificates curl
EXPOSE 8080 8443
WORKDIR $WORKDIR
ENTRYPOINT ["/usr/local/bin/goma"]