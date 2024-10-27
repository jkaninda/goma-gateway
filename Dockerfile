FROM golang:1.23.2 AS build
WORKDIR /app
ARG appVersion=""
# Copy the source code.
COPY . .
# Installs Go dependencies
RUN go mod download

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-X 'util.Version=${appVersion}'" -o /app/goma

FROM alpine:3.20.3
ENV TZ=UTC
ARG WORKDIR="/config"
ARG CERTSDIR="${WORKDIR}/certs"
ARG appVersion=""
ARG user="goma"
ENV VERSION=${appVersion}
LABEL author="Jonas Kaninda"
LABEL version=${appVersion}
LABEL github="github.com/jkaninda/goma-gateway"


RUN apk --update add --no-cache tzdata ca-certificates curl
RUN mkdir -p ${WORKDIR} ${CERTSDIR} && \
     chmod a+rw ${WORKDIR} ${CERTSDIR}
COPY --from=build /app/goma /usr/local/bin/goma
RUN chmod +x /usr/local/bin/goma && \
    ln -s /usr/local/bin/goma /usr/bin/goma
RUN addgroup -S ${user} && adduser -S ${user} -G ${user}

USER ${user}
WORKDIR $WORKDIR
ENTRYPOINT ["/usr/local/bin/goma"]