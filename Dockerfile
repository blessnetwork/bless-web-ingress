# Stage 1: Build the project
FROM golang:bookworm AS builder

# Set the working directory
WORKDIR /app

# Copy the project files
COPY . .

# Build the project
RUN go build -o bless-web-ingress main.go

# Stage 2: Create the final image
FROM debian:bookworm-slim

# Set the working directory
WORKDIR /app

# Copy the built executable from the builder stage
COPY --from=builder /app/bless-web-ingress .

# Expose the application port
EXPOSE 8080

# Run the executable
CMD ["./bless-web-ingress"]
