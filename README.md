========================================================================

File name    : rdp_parser.py

Description  : Parse RDP login events from .evtx logs and enrich with GeoIP.

Target : Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational

========================================================================

pip install evtx

pip install geoip2

pip install pyinstaller

========================================================================

pyinstaller --onefile rdp_parser.py

========================================================================

rdp_parser.py -i Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
  * The GeoLite2-Country.mmdb file must be placed in the same directory as the rdp_parser.py and rdp_parser.exe files.

"Two files, rdp_log.csv and rdp_log_stats.csv, will be generated."
