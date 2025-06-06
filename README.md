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
