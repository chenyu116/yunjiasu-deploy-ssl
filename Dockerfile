FROM ccr.ccs.tencentyun.com/astatium.com/golang:1.13.9-alpine3.11 AS build_deps

RUN apk add --no-cache git

WORKDIR /mnt
ENV GO111MODULE=on

COPY go.mod .
COPY go.sum .

RUN go mod download

FROM build_deps AS build

COPY . .

RUN CGO_ENABLED=0 go build -o webhook -ldflags '-w -extldflags "-static"' .

FROM ccr.ccs.tencentyun.com/astatium.com/alpine:3.11.5

RUN apk add --no-cache ca-certificates tzdata && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
    && echo "Asia/Shanghai" > /etc/timezone \
    && apk del tzdata

COPY --from=build /mnt/webhook /usr/local/bin/webhook

ENTRYPOINT ["webhook"]
