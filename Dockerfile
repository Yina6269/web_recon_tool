# Use the official Golang image as a base
FROM golang:1.20-alpine

# Set the working directory inside the container
WORKDIR /app

# Copy the Go modules manifest files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the project source code
COPY . .

# Build the Go application
RUN go build -o web_recon .

# Expose the port your application listens on (if applicable, e.g., 8080 for a web interface)
EXPOSE 0.0.0.0

# Run the executable
CMD ["./web_recon", "--mode", "full", "--host", "http://testphp.vulnweb.com"]
