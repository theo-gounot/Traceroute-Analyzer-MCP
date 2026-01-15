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
            return []

        if df.empty:
            return []

        enriched_path = []
        previous_hop = None

        for _, row in df.iterrows():
            ip = row["ip_address"]
            is_private = self._is_private_ip(ip)
            
            hop_data = {
                "ttl": int(row["ttl"]),
                "ip_address": ip,
                "rtt_ms": float(row["rtt_ms"]) if pd.notna(row["rtt_ms"]) else 0.0,
                "is_private": is_private,
                "metadata": {}
            }

            if pd.notna(row["city"]):
                hop_data["metadata"] = {
                    "city": row["city"],
                    "country": row["country_name"],
                    "isp": row["isp"],
                    "asn": row["asn_name"],
                    "latitude": row["latitude"],
                    "longitude": row["longitude"]
                }
            
            analysis = {}
            if previous_hop:
                curr_rtt = hop_data["rtt_ms"]
                prev_rtt = previous_hop["rtt_ms"]
                # Only calculate spike if both have valid RTT
                if curr_rtt is not None and prev_rtt is not None:
                    rtt_diff = curr_rtt - prev_rtt
                    analysis["rtt_spike_ms"] = round(rtt_diff, 2)
                
                prev_meta = previous_hop.get("metadata", {})
                curr_meta = hop_data.get("metadata", {})
                
                if prev_meta and curr_meta:
                    if prev_meta.get("country") != curr_meta.get("country"):
                         analysis["geographic_jump"] = f"{prev_meta.get('country')} -> {curr_meta.get('country')}"

            hop_data["analysis"] = analysis
            enriched_path.append(hop_data)
            previous_hop = hop_data

        return enriched_path

    def generate_topology(self, test_uuid):
        path = self.get_enriched_path(test_uuid)
        if not path:
            return "graph LR\n    Start --> End"

        mermaid_lines = ["graph LR"]
        for hop in path:
            node_id = f"hop_{hop['ttl']}"
            label = hop['ip_address']
            if hop['is_private']:
                label += "\\n(Private)"
            elif hop['metadata']:
                city = hop['metadata'].get('city') or "Unknown City"
                country = hop['metadata'].get('country') or "Unknown Country"
                isp = hop['metadata'].get('isp') or "Unknown ISP"
                label = f"{city}, {country}\\n{isp}"
            
            # Escape quotes in label
            label = label.replace('"', "'")
            mermaid_lines.append(f'    {node_id}["{label}"]')

        for i in range(len(path) - 1):
            u = f"hop_{path[i]['ttl']}"
            v = f"hop_{path[i+1]['ttl']}"
            weight = path[i+1]['rtt_ms']
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
            return []
            
        anomalies = []
        for _, row in df.iterrows():
            reasons = []
            if row.get("threat_is_datacenter") in [True, 1, 'true', 'True']:
                reasons.append("High Probability of Datacenter/Proxy (threat_is_datacenter=True)")
            
            if row.get("threat_is_tor") in [True, 1, 'true', 'True']:
                reasons.append("Known Tor Exit Node (threat_is_tor=True)")

            if row.get("threat_is_proxy") in [True, 1, 'true', 'True']:
                reasons.append("Known Public Proxy (threat_is_proxy=True)")
            
            if reasons:
                anomalies.append({
                    "ttl": int(row["ttl"]),
                    "ip_address": row["ip_address"],
                    "asn": row.get("asn_name"),
                    "reasons": reasons
                })
        return anomalies
