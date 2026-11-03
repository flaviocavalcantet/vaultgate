FROM golang:1.26 AS build
WORKDIR /src
# Modules first, checked against go.sum, so they are cached across source changes.
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN CGO_ENABLED=0 go build -o /out/scanner ./cmd/scanner && \
    CGO_ENABLED=0 go build -o /out/worker ./cmd/worker

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/scanner /out/worker /
# The CLI by default; the worker runs with --entrypoint /worker (compose does).
ENTRYPOINT ["/scanner"]
