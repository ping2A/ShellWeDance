# ShellWeDance: WASM PowerShell analyzer only (nginx)
# Build: docker build -t shell-we-dance .
# Run:   docker run -p 8080:80 shell-we-dance
# Open:  http://localhost:8080/

FROM rust:1-bookworm AS wasm-builder

RUN cargo install wasm-pack

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY shell-we-dance-ps ./shell-we-dance-ps
COPY wasm ./wasm

RUN wasm-pack build wasm --release --out-dir pkg --target web

COPY indicators ./indicators
COPY scripts/generate_rules_yml.sh ./scripts/generate_rules_yml.sh
RUN bash scripts/generate_rules_yml.sh

FROM nginx:alpine

# Register .wasm without a server-level `types {}` block (that would drop .js MIME)
RUN grep -q 'application/wasm' /etc/nginx/mime.types || \
    sed -i '/application\/javascript[[:space:]]*js;/a\    application/wasm wasm;' /etc/nginx/mime.types

COPY docker/nginx-wasm.conf /etc/nginx/conf.d/default.conf
COPY docker/entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

COPY --from=wasm-builder /app/wasm /usr/share/nginx/html

EXPOSE 80

ENTRYPOINT ["/docker-entrypoint.sh"]
