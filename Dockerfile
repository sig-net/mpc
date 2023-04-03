FROM rust:latest
WORKDIR /usr/src/app
COPY . .
RUN cargo install --path mpc-recovery/
RUN mv /usr/local/cargo/bin/mpc-recovery /usr/local/bin/mpc-recovery
WORKDIR /usr/local/bin

ENTRYPOINT [ "mpc-recovery" ]