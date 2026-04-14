FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod main.go ./
RUN go build -o /ingest-gateway .

FROM alpine:3.19
COPY --from=build /ingest-gateway /usr/local/bin/ingest-gateway
EXPOSE 8081
ENTRYPOINT ["/usr/local/bin/ingest-gateway"]
