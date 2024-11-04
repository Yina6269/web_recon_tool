
FROM golang:1.20-alpine


WORKDIR /app


COPY go.mod go.sum ./
RUN go mod download


COPY . .


RUN go build -o web_recon .

EXPOSE 8080


CMD ["./web_recon", "--mode", "full", "--host", "0.0.0.0", "--port", "${PORT:-8080}", "--target", "http://testphp.vulnweb.com"]

