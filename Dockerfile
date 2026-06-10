FROM golang:1.24-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /build/call-policy-default ./cmd/module

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /build/call-policy-default /
ENTRYPOINT ["/call-policy-default"]
