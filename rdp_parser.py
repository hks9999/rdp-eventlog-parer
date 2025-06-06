# -*- coding: utf-8 -*-

"""
===============================================================================
File name    : rdp_parser.py
Description  : Parse RDP login events from .evtx logs and enrich with GeoIP.
Target : Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational
===============================================================================
pip install evtx
pip install geoip2
pip install pyinstaller
===============================================================================
pyinstaller --onefile --noconsole rdp_parser.py
===============================================================================
rdp_parser.py -i Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
"""

import argparse
import os
import sys
from datetime import datetime, timezone, timedelta
import xml.etree.ElementTree as ET

from Evtx.Evtx import Evtx
import geoip2.database

# ------------------- Helper Functions -------------------

def get_geoip_info(reader, ip):
    try:
        response = reader.city(ip)
        country = response.country.iso_code or 'N/A'
        city = response.city.name or 'N/A'
        org = response.traits.organization or 'N/A'
        return f"{country}, {city}, {org}"
    except Exception as e:
        print(f"[GeoIP Lookup Failed] IP: {ip}, Reason: {e}")
        return "Unknown"

def parse_evtx(evtx_path, reader):
    KST = timezone(timedelta(hours=9))
    ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event', 'user': 'Event_NS'}

    event_rows = []
    ip_user_stats = {}

    with Evtx(evtx_path) as log:
        for record in log.records():
            try:
                root = ET.fromstring(record.xml())
                eventid_node = root.find(".//ns:System/ns:EventID", ns)
                if eventid_node is None or eventid_node.text not in {"21", "25"}:
                    continue

                eventid = eventid_node.text
                computername = root.find(".//ns:System/ns:Computer", ns).text
                utc_time_str = root.find(".//ns:System/ns:TimeCreated", ns).attrib["SystemTime"]

                user_node = root.find(".//user:User", ns)
                user = user_node.text.strip() if user_node is not None and user_node.text else "N/A"

                ip_node = root.find(".//user:Address", ns)
                ip_address = ip_node.text.strip() if ip_node is not None and ip_node.text else "N/A"

                time_utc = datetime.strptime(utc_time_str[:19], "%Y-%m-%d %H:%M:%S")
                kst_dt = time_utc.replace(tzinfo=timezone.utc).astimezone(KST)
                time_kst = kst_dt.strftime("%Y-%m-%d %H:%M:%S")

                whois_info = get_geoip_info(reader, ip_address) if ip_address not in ("N/A", "LOCAL") else "None"

                event_rows.append({
                    "eventid": eventid,
                    "computername": computername,
                    "time_kst": time_kst,
                    "user": user,
                    "ip_address": ip_address,
                    "whois": whois_info,
                    "time_obj": kst_dt
                })

                key = (ip_address, user)
                if ip_address not in ("N/A", "LOCAL"):
                    if key not in ip_user_stats:
                        ip_user_stats[key] = {
                            "whois": whois_info,
                            "first_seen": time_kst,
                            "last_seen": time_kst,
                            "first_seen_obj": kst_dt,
                            "last_seen_obj": kst_dt,
                            "count": 1
                        }
                    else:
                        if kst_dt < ip_user_stats[key]["first_seen_obj"]:
                            ip_user_stats[key]["first_seen"] = time_kst
                            ip_user_stats[key]["first_seen_obj"] = kst_dt
                        if kst_dt > ip_user_stats[key]["last_seen_obj"]:
                            ip_user_stats[key]["last_seen"] = time_kst
                            ip_user_stats[key]["last_seen_obj"] = kst_dt
                        ip_user_stats[key]["count"] += 1

            except Exception as e:
                print(f"[Error] Failed to process record: {e}")
                continue

    event_rows.sort(key=lambda x: x["time_obj"])
    return event_rows, ip_user_stats

def write_csv_logs(event_rows, output_path):
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        f.write("eventid,computername,time_kst,user,ip_address,whois\n")
        for row in event_rows:
            f.write(f'"{row["eventid"]}","{row["computername"]}","{row["time_kst"]}","{row["user"]}","{row["ip_address"]}","{row["whois"]}"\n')

def write_csv_stats(ip_user_stats, output_path):
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        f.write("ip_address,user,whois,first_seen,last_seen,count\n")
        for (ip, user), stats in ip_user_stats.items():
            f.write(f'"{ip}","{user}","{stats["whois"]}","{stats["first_seen"]}","{stats["last_seen"]}","{stats["count"]}"\n')

# ------------------- Main Entry Point -------------------

def main():
    parser = argparse.ArgumentParser(description="RDP EVTX log parser with GeoIP enrichment")
    parser.add_argument("-i", "--input", required=True, help="Path to input .evtx file")
    parser.add_argument("-g", "--geoip", default="GeoLite2-City.mmdb", help="Path to GeoIP DB file (default: GeoLite2-City.mmdb)")
    parser.add_argument("-o", "--output", default=".", help="Output directory (default: current directory)")

    args = parser.parse_args()

    evtx_path = args.input
    geoip_path = args.geoip
    output_dir = args.output

    if not os.path.exists(evtx_path):
        print(f"[Error] EVTX file not found: {evtx_path}")
        sys.exit(1)

    if not os.path.exists(geoip_path):
        print(f"[Error] GeoIP database not found: {geoip_path}")
        sys.exit(1)

    os.makedirs(output_dir, exist_ok=True)

    print("[Info] Parsing log...")

    reader = geoip2.database.Reader(geoip_path)
    event_rows, ip_user_stats = parse_evtx(evtx_path, reader)

    log_csv_path = os.path.join(output_dir, "rdp_log.csv")
    stats_csv_path = os.path.join(output_dir, "rdp_log_stats.csv")

    write_csv_logs(event_rows, log_csv_path)
    write_csv_stats(ip_user_stats, stats_csv_path)

    print(f"\n[Done] Log saved: {log_csv_path}")
    print(f"[Done] Statistics saved: {stats_csv_path}")

if __name__ == "__main__":
    main()
