FROM golang:1.26-alpine AS builder
COPY core/ /build/core/
COPY call-policy-default/ /build/call-policy-default/
WORKDIR /build/call-policy-default
RUN go mod download
RUN CGO_ENABLED=0 go build -o /call-policy-default ./cmd/module

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
RUN adduser -D -h /app policy
USER policy
WORKDIR /app
COPY --from=builder /call-policy-default .
COPY call-policy-default/policies.yaml .
EXPOSE 9300
ENTRYPOINT ["./call-policy-default"]
