# Use an official Python runtime as a parent image
FROM python:3.13-slim

# Set environment variables for Python
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set the working directory in the container
WORKDIR /app

# Install system dependencies needed for downloading and installing cloudflared
ENV CLOUDFLARED_VERSION="2024.1.5"

RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    ca-certificates \
    # Clean up apt cache to reduce image size
    && rm -rf /var/lib/apt/lists/* \
    # Dynamically determine architecture and download the appropriate cloudflared binary
    && ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then \
        CLOUDFLARED_ARCH="linux-amd64"; \
    elif [ "$ARCH" = "arm64" ]; then \
        CLOUDFLARED_ARCH="linux-arm64"; \
    else \
        echo "Unsupported architecture: $ARCH" && exit 1; \
    fi && \
    wget -q https://github.com/cloudflare/cloudflared/releases/download/${CLOUDFLARED_VERSION}/cloudflared-$CLOUDFLARED_ARCH.deb && \
    dpkg -i cloudflared-$CLOUDFLARED_ARCH.deb && \
    rm cloudflared-$CLOUDFLARED_ARCH.deb && \
    cloudflared --version && \
    mkdir -p /root/.cloudflared && \
    echo "Created /root/.cloudflared directory"

# Create static directory and copy files
RUN mkdir -p /app/static
COPY static/ /app/static/
COPY templates/ /app/templates/

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY app.py .

# Expose port 5000
EXPOSE 5000

# Run the application
CMD ["python", "app.py"]