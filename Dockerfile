FROM rust:latest
WORKDIR /usr/src/app
RUN echo "fn main() {}" > dummy.rs
COPY mpc-recovery/Cargo.toml Cargo.toml
RUN sed -i 's#src/main.rs#dummy.rs#' Cargo.toml
RUN cargo build --release
COPY . .
RUN cargo install --path mpc-recovery/
RUN mv /usr/local/cargo/bin/mpc-recovery /usr/local/bin/mpc-recovery
WORKDIR /usr/local/bin

ENTRYPOINT [ "mpc-recovery" ]