FROM python:3.11-slim

WORKDIR /app

# Install system dependencies if needed (e.g. for psycopg2 if we switched from binary)
# Using psycopg2-binary so strictly not needed, but good practice for slim images if we expand.
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Add src to PYTHONPATH so python can find modules
ENV PYTHONPATH=/app/src

# Default environment variables (can be overridden)
ENV MCP_HOST=0.0.0.0
ENV MCP_PORT=8000

EXPOSE 8000

# Default entrypoint runs the server
ENTRYPOINT ["python", "src/server.py"]

# Default command runs in SSE mode
CMD ["sse"]
