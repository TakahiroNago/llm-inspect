# Build from the repository root:
#   docker build -f crates/llm-inspect-server/Dockerfile -t llm-inspect-server .
# Run:
#   docker run --rm -p 8080:8080 -e LLM_INSPECT_TOKEN=change-me llm-inspect-server

FROM rust:1-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p llm-inspect-server

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/llm-inspect-server /usr/local/bin/llm-inspect-server
ENV LLM_INSPECT_BIND=0.0.0.0:8080
EXPOSE 8080
USER nonroot
ENTRYPOINT ["/usr/local/bin/llm-inspect-server"]
