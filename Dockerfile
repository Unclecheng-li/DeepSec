FROM rust:1-bookworm AS tui-build

WORKDIR /build/tui
COPY tui/Cargo.toml tui/Cargo.lock ./
COPY tui/src ./src
RUN cargo build --release --locked

FROM python:3.12-slim

ENV HOME=/data \
    DEEPSEC_HOME=/data \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /opt/deepsec
COPY pyproject.toml README.md DEEPSEC.md LICENSE ./
COPY deepsec ./deepsec
RUN pip install --no-cache-dir .
COPY --from=tui-build /build/tui/target/release/deepsec-tui-native /usr/local/bin/deepsec-tui-native

WORKDIR /workspace
ENTRYPOINT ["deepsec"]
CMD ["tui"]
