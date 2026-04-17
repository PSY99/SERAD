import csv
from typing import Dict, Any, Optional


# Shared schema used in SERDGRAD for network alarm normalization
SHARED_SCHEMA = [
    "timestamp",
    "source_ip",
    "source_port",
    "destination_ip",
    "destination_port",
    "protocol",
    "alert_type",
    "signature",
    "severity",
    "service",
]


# Representative field-mapping dictionary for heterogeneous alarm sources
FIELD_MAPPING_DICT = {
    # timestamp
    "timestamp": "timestamp",
    "time": "timestamp",
    "event_time": "timestamp",
    "@timestamp": "timestamp",

    # source IP
    "src_ip": "source_ip",
    "source_ip": "source_ip",
    "source_address": "source_ip",
    "sip": "source_ip",

    # source port
    "src_port": "source_port",
    "source_port": "source_port",
    "sport": "source_port",

    # destination IP
    "dst_ip": "destination_ip",
    "dest_ip": "destination_ip",
    "destination_ip": "destination_ip",
    "destination_address": "destination_ip",
    "dip": "destination_ip",

    # destination port
    "dst_port": "destination_port",
    "dest_port": "destination_port",
    "destination_port": "destination_port",
    "dport": "destination_port",

    # protocol
    "proto": "protocol",
    "protocol": "protocol",
    "transport": "protocol",

    # alert/category fields
    "alert_type": "alert_type",
    "attack_category": "alert_type",
    "category": "alert_type",
    "event_type": "alert_type",

    # signature/message
    "signature": "signature",
    "alert_signature": "signature",
    "message": "signature",
    "msg": "signature",

    # severity
    "severity": "severity",
    "priority": "severity",
    "risk": "severity",
}


def load_port_service_map(csv_path: str) -> Dict[int, str]:
    """
    Load a simple port-to-service mapping from port_service.csv.
    Only single numeric ports are used; ranged ports are skipped for simplicity.
    """
    port_map = {}

    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            port_text = row["Port"].strip()

            # Skip ranges such as "71–74" or "42081-42090"
            if not port_text.isdigit():
                continue

            port = int(port_text)
            description = row["Description"].strip()
            if description:
                # Keep only a short service label before the first punctuation
                service_name = description.split(";")[0].split(",")[0].split("(")[0].strip()
                port_map[port] = service_name

    return port_map


def normalize_protocol(value: Any) -> Optional[str]:
    if value is None:
        return None
    return str(value).strip().upper()


def normalize_int(value: Any) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def normalize_alarm(raw_alarm: Dict[str, Any], port_service_map: Dict[int, str]) -> Dict[str, Any]:
    """
    Normalize a heterogeneous network alarm into the shared schema.
    """
    normalized = {field: None for field in SHARED_SCHEMA}

    # Rule-based field mapping
    for raw_key, raw_value in raw_alarm.items():
        key = raw_key.strip()
        if key in FIELD_MAPPING_DICT:
            shared_key = FIELD_MAPPING_DICT[key]
            normalized[shared_key] = raw_value

    # Type normalization
    normalized["protocol"] = normalize_protocol(normalized["protocol"])
    normalized["source_port"] = normalize_int(normalized["source_port"])
    normalized["destination_port"] = normalize_int(normalized["destination_port"])

    # Optional service enrichment from destination port
    dport = normalized["destination_port"]
    if dport is not None and dport in port_service_map:
        normalized["service"] = port_service_map[dport]

    return normalized


if __name__ == "__main__":
    port_service_map = load_port_service_map("port_service.csv")

    # Example alarms from different products with heterogeneous field names
    alarm_1 = {
        "timestamp": "2024-11-11 16:10:00",
        "src_ip": "192.168.50.5",
        "src_port": "50714",
        "dst_ip": "192.168.50.60",
        "dst_port": "1521",
        "proto": "tcp",
        "attack_category": "Potentially-Bad-Traffic",
        "signature": "ET SCAN Suspicious inbound to Oracle SQL port 1521",
        "severity": 2,
    }

    alarm_2 = {
        "event_time": "2024-11-11T16:10:00Z",
        "source_address": "192.168.50.5",
        "sport": 50714,
        "destination_address": "192.168.50.60",
        "dport": 1521,
        "protocol": "TCP",
        "category": "Potentially-Bad-Traffic",
        "msg": "ET SCAN Suspicious inbound to Oracle SQL port 1521",
        "priority": 2,
    }

    print("Normalized alarm 1:")
    print(normalize_alarm(alarm_1, port_service_map))
    print()

    print("Normalized alarm 2:")
    print(normalize_alarm(alarm_2, port_service_map))
