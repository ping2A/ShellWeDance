#!/bin/sh
set -e
echo ""
echo "Shell We Dance — WASM UI (PowerShell analyzer)"
echo "  Nginx is listening on port 80 inside the container."
echo "  Example:  docker run -p 8080:80 shell-we-dance"
echo "  Then open: http://localhost:8080/"
echo ""
exec nginx -g "daemon off;"
