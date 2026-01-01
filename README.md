# Traceroute Analyser MCP Server

An MCP (Model Context Protocol) server designed for the **LAND-UFRJ** lab to provide AI agents with Geographic Path Analysis capabilities. It merges raw network telemetry from Raspberry Pi fleets with rich infrastructure metadata to monitor network performance and security.

## Features

- **Path Enrichment**: Joins hop-by-hop traceroute data with GeoIP and ASN metadata. Identifies geographic jumps (e.g., Brazil to USA) and correlates them with RTT spikes.
- **Topology Visualization**: Generates Mermaid.js `graph LR` strings where nodes are labeled with `[City, Country | ISP]` and edges are weighted by latency.
- **Anomaly Detection**: Flags hops passing through datacenters, proxies, or unexpected transit providers in the Brazilian Academic Network (RNP) context.
- **Context-Aware Prompts**: Includes specialized prompt templates for:
    - **Performance Diagnosis**: Root-cause analysis of latency bottlenecks.
    - **Security Audits**: Infrastructure and chain-of-trust verification.
    - **Data Sovereignty**: Detecting "boomerang routing" outside national jurisdictions.
    - **Peering Analysis**: Inspecting handoffs between academic and commercial networks.

## Prerequisites

- Python 3.10+
- PostgreSQL/TimescaleDB (containing `traceroute_telemetry` and `ip_metadata` tables)

## Installation

1. **Clone the repository.**
2. **Set up a virtual environment and install dependencies:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # On Linux
   pip install -r requirements.txt
   ```
3. **Configure the environment:**
   Create a `.env` file in the root directory and fill in your database and server credentials.

## Configuration

Edit `.env` to set your Database and MCP Server configuration:

```env
DB_HOST=your_db_host
DB_PORT=5432
DB_NAME=your_db_name
DB_USER=your_db_user
DB_PASSWORD=your_db_password

MCP_HOST=0.0.0.0
MCP_PORT=8000
```

## Usage

### Local Mode (stdio)
Recommended for use with AI clients like Claude Desktop:
```bash
.venv/bin/python src/server.py
```

### Network Mode (SSE)
To run as a network server using the host and port defined in `.env`:
```bash
.venv/bin/python src/server.py sse
```

## Docker Support

### Running with Docker Compose

This project includes a Docker setup that runs the MCP server. **It assumes you have a PostgreSQL database running externally.**

1.  **Configure `.env`:**
    Ensure your `.env` file points to your running database. 
    *   If your database is on your host machine (localhost), use `DB_HOST=host.docker.internal`.
    *   If your database is on another server, use its IP address or hostname.

    ```env
    DB_HOST=host.docker.internal
    # ... other DB credentials
    ```

2.  **Build and Run:**
    ```bash
    docker-compose up -d --build
    ```

3.  **Access:**
    The server will be available at `http://localhost:8000/sse`.

### Running Manually with Docker

1.  **Build the image:**
    ```bash
    docker build -t traceroute-analyser .
    ```

2.  **Run the container:**
    ```bash
    # Example connecting to host database
    docker run -p 8000:8000 --env-file .env --add-host=host.docker.internal:host-gateway traceroute-analyser
    ```