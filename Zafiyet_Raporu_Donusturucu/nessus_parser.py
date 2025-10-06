import xml.etree.ElementTree as ET
from models import Host, Vulnerability, VulnerabilityHistory
from datetime import datetime
from sqlalchemy.orm import Session

def parse_nessus(file_path: str, session: Session):
    tree = ET.parse(file_path)
    root = tree.getroot()

    count_new = 0

    # mevcut vuln'ları eşleştirmek için map
    existing_vulns = {}
    for v in session.query(Vulnerability).all():
        key = (v.host.ip, v.name, v.cve)
        existing_vulns[key] = v

    seen_keys = set()

    for h in root.findall(".//ReportHost"):
        host_ip = h.get("name") or ""
        props = {}
        hp = h.find("HostProperties")
        if hp is not None:
            for tag in hp.findall("tag"):
                props[tag.get("name")] = tag.text

        hostname = props.get("host-fqdn") or props.get("netbios-name") or ""
        os_info = props.get("operating-system") or ""
        company = props.get("organization") or ""

        # host var mı kontrol
        host = session.query(Host).filter_by(ip=host_ip).first()
        if not host:
            host = Host(ip=host_ip, hostname=hostname, os=os_info, company=company, created_at=datetime.utcnow())
            session.add(host)
            session.flush()

        for item in h.findall("ReportItem"):
            risk = item.findtext("risk_factor") or ""
            sev_map = {"0": "Info", "1": "Low", "2": "Medium", "3": "High", "4": "Critical"}
            if not risk:
                risk = sev_map.get(item.get("severity"), "Info")

            cves = [c.text for c in item.findall("cve") if c.text]
            cve_str = ", ".join(cves)

            plugin_name = item.get("pluginName") or ""

            key = (host_ip, plugin_name, cve_str)
            seen_keys.add(key)

            if key in existing_vulns:
                vuln = existing_vulns[key]
                if vuln.status == "closed":
                    vuln.status = "open"
                    session.add(VulnerabilityHistory(vuln_id=vuln.id, status="reopened"))
            else:
                vuln = Vulnerability(
                    host_id=host.id,
                    cve=cve_str,
                    risk=risk,
                    protocol=item.get("protocol") or "",
                    port=item.get("port") or "",
                    name=plugin_name,
                    synopsis=item.findtext("synopsis") or "",
                    solution=item.findtext("solution") or "",
                    status="open"
                )
                session.add(vuln)
                session.flush()
                session.add(VulnerabilityHistory(vuln_id=vuln.id, status="open"))
                count_new += 1

    # eski açık bulgular yeni raporda yoksa → closed
    for key, vuln in existing_vulns.items():
        if key not in seen_keys and vuln.status == "open":
            vuln.status = "closed"
            session.add(VulnerabilityHistory(vuln_id=vuln.id, status="closed"))

    session.commit()
    return count_new