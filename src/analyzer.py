import pandas as pd
import ipaddress
import logging

logger = logging.getLogger("Traceroute-Analyser")

class TracerouteAnalyzer:
    def __init__(self, db_connector):
        """
        :param db_connector: A context manager that yields a database connection (psycopg2).
        """
        self.db_connector = db_connector

    def _is_private_ip(self, ip):
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    def get_enriched_path(self, test_uuid):
        # Adjusted query: 
        # 1. Use 'traceroute' table for hops.
        # 2. Join 'ip_geolocation' for metadata.
        # 3. No 'ip_metadata' table exists.
        query = """
            SELECT 
                t.ttl, t.ip_address, t.rtt_ms,
                g.city, g.region_name, g.country_name, g.latitude, g.longitude,
                g.asn_name, g.isp, g.asn_type,
                g.threat_is_datacenter, g.threat_is_tor, g.threat_is_proxy
            FROM traceroute t
            LEFT JOIN ip_geolocation g ON t.ip_address = g.ip_address
            WHERE t.ndt_test_uuid = %s
            ORDER BY t.ttl ASC
        """
        
        try:
            with self.db_connector() as conn:
                df = pd.read_sql(query, conn, params=(test_uuid,))
        except Exception as e:
            logger.error(f"Database error in get_enriched_path: {e}")
            return pd.DataFrame()

        if df.empty:
            return pd.DataFrame()

        # 1. Private IP Check
        df['is_private'] = df['ip_address'].apply(self._is_private_ip)

        # 2. RTT Spike
        # Calculate difference, round to 2 decimals. Handle first row (NaN) by filling with 0 or keeping NaN.
        # Logic matches old: diff between curr and prev.
        df['rtt_spike_ms'] = df['rtt_ms'].diff().round(2)

        # 3. Geographic Jump
        df['prev_country'] = df['country_name'].shift()
        
        def calculate_jump(row):
            if pd.notna(row['country_name']) and pd.notna(row['prev_country']):
                if row['country_name'] != row['prev_country']:
                    return f"{row['prev_country']} -> {row['country_name']}"
            return ""

        df['geographic_jump'] = df.apply(calculate_jump, axis=1)

        # Select and Rename Columns
        output_columns = {
            'ttl': 'ttl',
            'ip_address': 'ip_address',
            'rtt_ms': 'rtt_ms',
            'is_private': 'is_private',
            'city': 'city',
            'country_name': 'country',
            'isp': 'isp',
            'asn_name': 'asn',
            'latitude': 'latitude',
            'longitude': 'longitude',
            'rtt_spike_ms': 'rtt_spike_ms',
            'geographic_jump': 'geographic_jump'
        }
        
        # Ensure all columns exist (some might be missing from query if schema changed, but here we defined query)
        # Filter to only desired columns
        df_out = df[list(output_columns.keys())].rename(columns=output_columns)
        
        return df_out

    def generate_topology(self, test_uuid):
        # We need the DataFrame here. `get_enriched_path` now returns a DF.
        df = self.get_enriched_path(test_uuid)
        if df.empty:
            return "graph LR\n    Start --> End"

        mermaid_lines = ["graph LR"]
        
        # Iterate over DataFrame
        for _, hop in df.iterrows():
            node_id = f"hop_{int(hop['ttl'])}"
            label = hop['ip_address']
            if hop['is_private']:
                label += "\\n(Private)"
            elif pd.notna(hop['city']) or pd.notna(hop['country']):
                city = hop['city'] if pd.notna(hop['city']) else "Unknown City"
                country = hop['country'] if pd.notna(hop['country']) else "Unknown Country"
                isp = hop['isp'] if pd.notna(hop['isp']) else "Unknown ISP"
                label = f"{city}, {country}\\n{isp}"
            
            # Escape quotes in label
            label = label.replace('"', "'")
            mermaid_lines.append(f'    {node_id}["{label}"]')

        # Edges
        # We need access to next hop's RTT. 
        # In the loop, we can look ahead? Or just zip.
        # Converting to list of dicts for easy iteration might be simplest for this specific legacy function,
        # or just iterate index.
        
        records = df.to_dict('records')
        for i in range(len(records) - 1):
            u = f"hop_{int(records[i]['ttl'])}"
            v = f"hop_{int(records[i+1]['ttl'])}"
            weight = records[i+1]['rtt_ms']
            mermaid_lines.append(f"    {u} -- {weight}ms --> {v}")

        return "\n".join(mermaid_lines)

    def detect_anomalies(self, test_uuid):
        query = """
            SELECT 
                t.ttl, t.ip_address,
                g.asn_name, g.asn_type,
                g.threat_is_datacenter,
                g.threat_is_tor,
                g.threat_is_proxy
            FROM traceroute t
            LEFT JOIN ip_geolocation g ON t.ip_address = g.ip_address
            WHERE t.ndt_test_uuid = %s
        """
        
        try:
            with self.db_connector() as conn:
                df = pd.read_sql(query, conn, params=(test_uuid,))
        except Exception as e:
            logger.error(f"Database error in detect_anomalies: {e}")
            return pd.DataFrame()
            
        if df.empty:
            return pd.DataFrame()

        def get_reasons(row):
            reasons = []
            # Check for truthiness (handling booleans or 1/0 or strings)
            if row.get("threat_is_datacenter") in [True, 1, 'true', 'True']:
                reasons.append("High Probability of Datacenter/Proxy (threat_is_datacenter=True)")
            
            if row.get("threat_is_tor") in [True, 1, 'true', 'True']:
                reasons.append("Known Tor Exit Node (threat_is_tor=True)")

            if row.get("threat_is_proxy") in [True, 1, 'true', 'True']:
                reasons.append("Known Public Proxy (threat_is_proxy=True)")
            return "; ".join(reasons)

        df['reasons'] = df.apply(get_reasons, axis=1)
        
        # Filter rows with anomalies
        anomalies_df = df[df['reasons'] != ""].copy()
        
        # Select columns
        output_cols = ['ttl', 'ip_address', 'asn_name', 'reasons']
        anomalies_df = anomalies_df[output_cols].rename(columns={'asn_name': 'asn'})
        
        return anomalies_df
