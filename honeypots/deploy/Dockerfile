# Override with an approved, digest-pinned builder in your deployment pipeline.
ARG GO_IMAGE=golang:1.27.3-bookworm
FROM ${GO_IMAGE} AS build
WORKDIR /src
COPY go.mod ./
COPY internal ./internal
COPY vpn ./vpn
COPY uds-agent ./uds-agent
ARG TARGET=./vpn
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/honeypot ${TARGET}

FROM scratch
COPY --from=build /out/honeypot /honeypot
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/honeypot"]
CMD ["-listen", "0.0.0.0:8080"]
