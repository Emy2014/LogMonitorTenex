# Build
FROM golang:1.23 AS build
WORKDIR /src

# Dependencies first, so a source-only change does not re-download the module
# graph on every build.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# CGO off => a static binary that runs in a scratch image.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/gateway ./cmd/gateway

# Run
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/gateway /app/gateway
USER nonroot:nonroot
EXPOSE 8000
ENTRYPOINT ["/app/gateway"]
