FROM golang:1.16-alpine AS build

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY main.go ./
RUN go build -o /commandcenter

# DEPLOY
FROM alpine:latest

WORKDIR /

COPY --from=build /commandcenter /commandcenter

EXPOSE 8000

ENTRYPOINT ["/commandcenter"]