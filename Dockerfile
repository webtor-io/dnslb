FROM alpine:latest as certs

# getting certs
RUN apk update && apk upgrade && apk add --no-cache ca-certificates

FROM golang:latest as build

# set work dir
WORKDIR /app

# copy the source files
COPY . .

# disable crosscompiling 
ENV CGO_ENABLED=0

# compile linux only
ENV GOOS=linux

# build the binary with debug information removed
RUN go build -ldflags '-w -s' -a -installsuffix cgo -o dnslb

FROM scratch

# copy certs
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
# copy our static linked library
COPY --from=build /app/dnslb .

# run it!
CMD ["./dnslb"]