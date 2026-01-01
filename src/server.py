import os
import json
import logging
import psycopg2
from psycopg2 import pool
from contextlib import contextmanager
import pandas as pd
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
from analyzer import TracerouteAnalyzer

# --- Logging Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("Traceroute-Analyser-MCP")

# --- Environment & Configuration ---
load_dotenv()

DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
MCP_HOST = os.getenv("MCP_HOST", "0.0.0.0")
MCP_PORT = int(os.getenv("MCP_PORT", 8000))

# Initialize FastMCP
mcp = FastMCP(name="Traceroute-Analyser", host=MCP_HOST, port=MCP_PORT)

# --- Global State ---
_db_pool = None

# --- Initialization ---
def init_resources():
    """Initialize database pool."""
    global _db_pool
    
    # Init DB Pool
    try:
        if not _db_pool:
            _db_pool = psycopg2.pool.SimpleConnectionPool(
                minconn=1,
                maxconn=20,
                host=DB_HOST,
                port=DB_PORT,
                database=DB_NAME,
                user=DB_USER,
                password=DB_PASSWORD
            )
            logger.info("Database connection pool initialized.")
    except Exception as e:
        logger.error(f"Failed to initialize database pool: {e}")

# Call init immediately
init_resources()

# --- Database Helper ---
@contextmanager
def get_db_connection():
    """Yields a connection from the pool and ensures it's returned."""
    if _db_pool is None:
        init_resources()
        if _db_pool is None:
            raise Exception("Database pool is not initialized.")
    
    conn = _db_pool.getconn()
    try:
        yield conn
    finally:
        _db_pool.putconn(conn)

# Initialize Analyzer with DB connection context manager
analyzer = TracerouteAnalyzer(get_db_connection)

# --- SQL Helper Tools ---

@mcp.tool()
def list_tables() -> str:
    """List all available tables in the public schema of the database."""
    logger.info("Tool called: list_tables")
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT table_name 
                    FROM information_schema.tables 
                    WHERE table_schema = 'public'
                """)
                tables = [row[0] for row in cur.fetchall()]
        return json.dumps({"tables": tables})
    except Exception as e:
        logger.error(f"Error in list_tables: {e}")
        return f"Error listing tables: {str(e)}"

@mcp.tool()
def describe_table(table_name: str) -> str:
    """Get the column names, types, and a few sample rows for a specific table."""
    logger.info(f"Tool called: describe_table (table={table_name})")
    try:
        with get_db_connection() as conn:
            # Get column info
            query_cols = """
                SELECT column_name, data_type 
                FROM information_schema.columns 
                WHERE table_name = %s
            """
            df_cols = pd.read_sql(query_cols, conn, params=(table_name,))
            
            # Get sample rows
            # Validate table_name to prevent injection
            if not table_name.replace("_","").isalnum():
                 return "Error: Invalid table name."

            query_sample = f"SELECT * FROM {table_name} LIMIT 3"
            df_sample = pd.read_sql(query_sample, conn)
        
        return json.dumps({
            "columns": df_cols.to_dict(orient="records"),
            "sample_data": df_sample.to_dict(orient="records")
        }, default=str)
    except Exception as e:
        logger.error(f"Error in describe_table: {e}")
        return f"Error describing table {table_name}: {str(e)}"

# --- Analysis Tools ---

@mcp.tool()
def path_enrichment(test_uuids: list[str]) -> str:
    """
    Diagnose network latency and routing logic. Returns the physical path (Cities, Countries, ASNs) and calculates 'rtt_spike_ms' to pinpoint exactly 
    where delay is introduced. Use this to detect international hairpinning or inefficient transit.
    """
    # Handle single string input gracefully
    if isinstance(test_uuids, str):
        test_uuids = [test_uuids]

    results = {}
    for uuid in test_uuids:
        results[uuid] = analyzer.get_enriched_path(uuid)

    return json.dumps(results, indent=2)

@mcp.tool()
def topology_visualization(test_uuid: str) -> str:
    """
    Visualize the network topology. Returns a Mermaid.js graph string showing hops, latencies, and geographic nodes. Use this to show the user a 
    map of how their traffic flows.
    """
    return analyzer.generate_topology(test_uuid)

@mcp.tool()
def anomaly_detection(test_uuid: str) -> str:
    """
    Audit the route for security and policy violations. Detects 'boomerang' routing (traffic leaving the country), unauthorized Datacenter/Proxy usage
    and unexpected ASN handoffs. Returns a list of flagged hops.
    """
    anomalies = analyzer.detect_anomalies(test_uuid)
    return json.dumps(anomalies, indent=2)

# --- Prompts ---

@mcp.prompt()
def diagnose_route_performance(test_uuid: str) -> str:
    """
    Guides the AI to perform a full root-cause analysis of network performance issues.
    """
    return f"""Please perform a comprehensive analysis of the traceroute for Test UUID: {test_uuid}.

Follow these steps to diagnose performance:
1. Call `path_enrichment({test_uuid})` to get the raw hop data. Analyze the 'rtt_spike_ms' fields to pinpoint exactly where latency occurs.
2. Call `topology_visualization({test_uuid})` to generate a visual map of the path.
3. Call `anomaly_detection({test_uuid})` to check for non-standard routing elements.

Based on the tool outputs, provide a report answering:
- **Latency Bottleneck:** Between which two hops (City/ISP pairs) does the latency spike occur?
- **Geographic Efficiency:** Does the packet leave the country unnecessarily (hairpinning)?
- **Sub-optimal Routing:** Is the path physically logical?
"""

@mcp.prompt()
def audit_path_security(test_uuid: str) -> str:
    """
    Guides the AI to perform a security audit of the network path.
    """
    return f"""Please perform a security and infrastructure audit for the route taken by Test UUID: {test_uuid}.

Steps:
1. Run `anomaly_detection({test_uuid})` immediately to identify flagged hops.
2. Run `path_enrichment({test_uuid})` to examine the full ASN/ISP chain.

Report Findings:
- **Threats:** Are there any IPs flagged as Datacenters, Proxies, or Tor nodes?
- **ISP Chain of Trust:** List the distinct ISPs involved. Does the traffic hand off between reputable carriers?
- **Jurisdiction:** List all unique countries the data passed through.
"""

@mcp.prompt()
def check_data_sovereignty(test_uuid: str) -> str:
    """
    Guides the AI to analyze if data leaves the expected national or regional jurisdiction.
    Useful for detecting 'hairpinning' or 'boomerang routing' (e.g., Brazil -> USA -> Brazil).
    """
    return f"""Analyze the geographic path of Test UUID: {test_uuid} for data sovereignty compliance.

1. Call `path_enrichment({test_uuid})` to get the country sequence.
2. Identify the Source Country (first public hop) and Destination Country (last hop).

Answer the following:
- **Route Integrity:** Does traffic passing between two points in the same country ever leave that country?
- **Jurisdiction List:** List every country code involved in the path.
- **Compliance Verdict:** If this was sensitive government data requiring local hosting, would this route be compliant?
"""

@mcp.prompt()
def analyze_peering_relationships(test_uuid: str) -> str:
    """
    Guides the AI to inspect the business relationships between networks (ASNs).
    Useful for understanding if traffic is staying on academic networks (RNP) or leaking to commercial transit.
    """
    return f"""Analyze the Autonomous System (ASN) handoffs for Test UUID: {test_uuid}.

1. Call `path_enrichment({test_uuid})` to retrieve the ASN for each hop.
2. Map the flow of traffic between organizations (e.g., University -> NREN -> Commercial Tier 1 -> ISP).

Provide an engineering assessment:
- **ASN Chain:** List the sequence of unique ASNs.
- **Peering Type:** Does it look like private peering (direct connection) or public transit?
- **Route Optimality:** Is the traffic traversing expensive commercial backbones when it should be staying on free academic peering links?
"""

if __name__ == "__main__":
    import sys
    # If the user provides "sse" as an argument, run as SSE server
    # Otherwise default to the standard MCP stdio transport
    if len(sys.argv) > 1 and sys.argv[1] == "sse":
        mcp.run(transport="sse")
    else:
        mcp.run(transport="stdio")