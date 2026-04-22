FROM python:3.12-slim

WORKDIR /app

# System dependencies for RE tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    binwalk \
    squashfs-tools \
    mtd-utils \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir -e ".[api,cli,tools]" 2>/dev/null || \
    pip install --no-cache-dir -e ".[api,cli]"

# Copy source
COPY core/ core/
COPY api/ api/
COPY cli/ cli/
COPY ghidra_scripts/ ghidra_scripts/

# Create upload directory
RUN mkdir -p uploads

EXPOSE 8000

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
