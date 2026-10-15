FROM golang:1.23 AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -o /out/scanner ./cmd/scanner

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/scanner /scanner
ENTRYPOINT ["/scanner"]
