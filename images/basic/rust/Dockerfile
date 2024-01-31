FROM rust:1.75.0
# Set the working directory
WORKDIR /app

# Copy the application files into the image
COPY Cargo.toml helloworld.rs ./

# Build the application in release mode
RUN cargo build --release

# Set the command to run the binary
CMD ["./target/release/hello-world"]