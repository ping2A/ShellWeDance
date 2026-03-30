# ShellWeDance: PowerShell command-line analyzer (WASM UI + CLI)
# Build: docker build -t shell-we-dance .
# Run:   docker run -p 8080:80 shell-we-dance
# Then open http://localhost:8080

# -----------------------------------------------------------------------------
# Stage 1: build CLI and WASM
# -----------------------------------------------------------------------------
FROM rust:1-bookworm AS builder

# Install wasm-pack for building the browser WASM module
RUN cargo install wasm-pack

WORKDIR /app

# Copy manifests and source
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY bin ./bin
COPY wasm ./wasm
COPY indicators ./indicators
COPY scripts ./scripts

# Build release binaries (CLI)
RUN cargo build --release

# Build WASM for the browser UI (release; --out-dir is relative to the crate, not WORKDIR)
RUN wasm-pack build wasm --release --out-dir pkg --target web

# Copy indicators into wasm/indicators and generate manifest.json
RUN bash scripts/generate_rules_yml.sh

# -----------------------------------------------------------------------------
# Stage 2: serve the WASM app with nginx
# -----------------------------------------------------------------------------
FROM nginx:alpine

# Ensure .wasm is served with correct MIME type (required for Chrome/Windows)
RUN echo "types { application/wasm wasm; }" > /etc/nginx/conf.d/wasm-mime.conf

# Serve the wasm app (index.html, pkg/, indicators/) at /
COPY --from=builder /app/wasm /usr/share/nginx/html

# Optional: include CLI for scripting (e.g. docker run ... shell-we-dance -r /indicators -c "...")
COPY --from=builder /app/target/release/shell-we-dance /usr/local/bin/

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
