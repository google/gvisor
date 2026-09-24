# The MCP server allowing OpenClaw to drive GNOME.
FROM debian:trixie

RUN set -eux; \
    export DEBIAN_FRONTEND=noninteractive; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        xvfb x11-utils xdotool scrot \
        tesseract-ocr tesseract-ocr-eng \
        freerdp3-x11 \
        python3 python3-pip \
        ca-certificates; \
    pip3 install --break-system-packages --no-cache-dir 'mcp>=2,<3' pillow pytesseract; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*

COPY desktop_mcp.py /opt/desktop-mcp/desktop_mcp.py
COPY entrypoint.sh /opt/desktop-mcp/entrypoint.sh
RUN chmod +x /opt/desktop-mcp/entrypoint.sh

ENV DISPLAY=:1 \
    SCREEN_WIDTH=1280 \
    SCREEN_HEIGHT=800 \
    PORT=8931

EXPOSE 8931
ENTRYPOINT ["/opt/desktop-mcp/entrypoint.sh"]
