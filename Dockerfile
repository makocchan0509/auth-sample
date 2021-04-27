FROM golang:1.16.3-alpine

RUN mkdir -p /go/src/sampleweb
WORKDIR /go/src/sampleweb
COPY  . .
RUN go get github.com/k-washi/jwt-decode/jwtdecode &&  GOOS=linux GOARCH=amd64 go build -o main main.go
#RUN go get -d -v ./... && go install -v ./..

EXPOSE 8080

CMD ["./main"]
