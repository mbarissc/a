import click
from db import SessionLocal, init_db
from models import Host, Vulnerability, User, VulnerabilityHistory
from nessus_parser import parse_nessus
from datetime import datetime
import pandas as pd
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

# ---------------- INIT ----------------
@click.command("init")
def init():
    init_db()
    click.echo("Database initialized.")

# ---------------- IMPORT ----------------
@click.command("import-nessus")
@click.argument("filename")
def import_nessus_cmd(filename):
    session = SessionLocal()
    count = parse_nessus(filename, session)
    click.echo(f"Imported {count} new vulnerabilities. Open/Closed statuses updated.")
    session.close()

# ---------------- HOSTS ----------------
@click.command("list-hosts")
@click.option("--company", default=None, help="Şirkete göre filtrele")
@click.option("--os", default=None, help="OS'e göre filtrele")
def list_hosts(company, os):
    session = SessionLocal()
    query = session.query(Host)
    if company:
        query = query.filter(Host.company.ilike(f"%{company}%"))
    if os:
        query = query.filter(Host.os.ilike(f"%{os}%"))
    hosts = query.all()
    for h in hosts:
        click.echo(f"[{h.id}] {h.ip} ({h.hostname}) OS={h.os} | Company={h.company}")
    session.close()

@click.command("add-host")
@click.argument("ip")
@click.option("--hostname", default="")
@click.option("--os", default="")
@click.option("--company", default="")
def add_host(ip, hostname, os, company):
    session = SessionLocal()
    host = Host(ip=ip, hostname=hostname, os=os, company=company, created_at=datetime.utcnow())
    session.add(host)
    session.commit()
    click.echo(f"Host eklendi: {host.id} {ip}")
    session.close()

@click.command("update-host")
@click.argument("host_id", type=int)
@click.option("--ip", default=None)
@click.option("--hostname", default=None)
@click.option("--os", default=None)
@click.option("--company", default=None)
def update_host(host_id, ip, hostname, os, company):
    session = SessionLocal()
    host = session.query(Host).get(host_id)
    if not host:
        click.echo("Host bulunamadı.")
        return
    if ip: host.ip = ip
    if hostname: host.hostname = hostname
    if os: host.os = os
    if company: host.company = company
    session.commit()
    click.echo(f"Host {host_id} güncellendi.")
    session.close()

@click.command("delete-host")
@click.argument("host_id", type=int)
def delete_host(host_id):
    session = SessionLocal()
    host = session.query(Host).get(host_id)
    if not host:
        click.echo("Host bulunamadı.")
        return
    session.delete(host)
    session.commit()
    click.echo(f"Host {host_id} silindi.")
    session.close()

# ---------------- VULNERABILITIES ----------------
@click.command("list-vulns")
@click.argument("host_id", type=int)
def list_vulns(host_id):
    session = SessionLocal()
    vulns = session.query(Vulnerability).filter_by(host_id=host_id).all()
    for v in vulns:
        click.echo(f"[{v.id}] {v.name} | {v.cve} | {v.risk} | {v.status} | action={v.action}")
    session.close()

@click.command("update-vuln")
@click.argument("vuln_id", type=int)
@click.argument("status")
def update_vuln(vuln_id, status):
    session = SessionLocal()
    v = session.query(Vulnerability).get(vuln_id)
    if not v:
        click.echo("Not found")
        return
    v.status = status
    session.add(VulnerabilityHistory(vuln_id=v.id, status=status))
    session.commit()
    click.echo(f"Vulnerability {vuln_id} updated to {status}")
    session.close()

@click.command("delete-vuln")
@click.argument("vuln_id", type=int)
def delete_vuln(vuln_id):
    session = SessionLocal()
    v = session.query(Vulnerability).get(vuln_id)
    if not v:
        click.echo("Not found")
        return
    session.delete(v)
    session.commit()
    click.echo("Deleted.")
    session.close()

@click.command("set-action")
@click.argument("vuln_id", type=int)
@click.argument("action")
def set_action(vuln_id, action):
    session = SessionLocal()
    v = session.query(Vulnerability).get(vuln_id)
    if not v:
        click.echo("Bulgu bulunamadı.")
        return
    v.action = action
    session.commit()
    click.echo(f"Bulgu {vuln_id} için aksiyon atandı: {action}")
    session.close()

@click.command("history")
@click.argument("vuln_id", type=int)
def history_cmd(vuln_id):
    session = SessionLocal()
    v = session.query(Vulnerability).get(vuln_id)
    if not v:
        click.echo("Bulgu bulunamadı.")
        return
    history_entries = session.query(VulnerabilityHistory).filter_by(vuln_id=vuln_id).order_by(VulnerabilityHistory.date).all()
    for h in history_entries:
        click.echo(f"{h.date.date()} - {h.status}")
    session.close()

# ---------------- USERS ----------------
@click.command("add-user")
@click.argument("username")
@click.option("--role", default="viewer", type=click.Choice(["admin","analyst","viewer"]))
def add_user(username, role):
    session = SessionLocal()
    u = User(username=username, role=role, created_at=datetime.utcnow())
    session.add(u)
    session.commit()
    click.echo(f"Kullanıcı eklendi: {u.id} {username} ({role})")
    session.close()

@click.command("list-users")
def list_users():
    session = SessionLocal()
    users = session.query(User).all()
    for u in users:
        click.echo(f"[{u.id}] {u.username} | role={u.role}")
    session.close()

@click.command("update-user")
@click.argument("user_id", type=int)
@click.option("--username", default=None)
@click.option("--role", type=click.Choice(["admin","analyst","viewer"]), default=None)
def update_user(user_id, username, role):
    session = SessionLocal()
    u = session.query(User).get(user_id)
    if not u:
        click.echo("Kullanıcı bulunamadı.")
        return
    if username: u.username = username
    if role: u.role = role
    session.commit()
    click.echo(f"Kullanıcı {user_id} güncellendi.")
    session.close()

@click.command("delete-user")
@click.argument("user_id", type=int)
def delete_user(user_id):
    session = SessionLocal()
    u = session.query(User).get(user_id)
    if not u:
        click.echo("Kullanıcı bulunamadı.")
        return
    session.delete(u)
    session.commit()
    click.echo(f"Kullanıcı {user_id} silindi.")
    session.close()

# ---------------- ASSIGN VULN ----------------
@click.command("assign-vuln")
@click.argument("vuln_id", type=int)
@click.argument("username")
def assign_vuln(vuln_id, username):
    session = SessionLocal()
    v = session.query(Vulnerability).get(vuln_id)
    u = session.query(User).filter_by(username=username).first()
    if not v or not u:
        click.echo("Vuln veya user bulunamadı.")
        return
    v.assigned_to = u.id
    session.commit()
    click.echo(f"Vuln {vuln_id} assigned to {username}")
    session.close()

@click.command("my-vulns")
@click.argument("username")
def my_vulns(username):
    session = SessionLocal()
    u = session.query(User).filter_by(username=username).first()
    if not u:
        click.echo("Kullanıcı bulunamadı.")
        return
    vulns = session.query(Vulnerability).filter_by(assigned_to=u.id).all()
    for v in vulns:
        click.echo(f"[{v.id}] {v.name} | {v.risk} | {v.status}")
    session.close()

# ---------------- RAPORLAMA ----------------
@click.command("summary")
def summary():
    session = SessionLocal()
    total_hosts = session.query(Host).count()
    total_vulns = session.query(Vulnerability).count()
    open_vulns = session.query(Vulnerability).filter_by(status="open").count()
    closed_vulns = session.query(Vulnerability).filter_by(status="closed").count()

    click.echo(f"Toplam Host: {total_hosts}")
    click.echo(f"Toplam Zafiyet: {total_vulns}")
    click.echo(f"Açık Zafiyet: {open_vulns}")
    click.echo(f"Kapatılmış Zafiyet: {closed_vulns}")
    session.close()

@click.command("export-csv")
@click.argument("filename")
def export_csv(filename):
    session = SessionLocal()
    vulns = session.query(Vulnerability).all()
    rows = []
    for v in vulns:
        rows.append({
            "id": v.id, "host_id": v.host_id, "name": v.name,
            "cve": v.cve, "risk": v.risk, "status": v.status,
            "protocol": v.protocol, "port": v.port,
            "synopsis": v.synopsis, "solution": v.solution,
            "action": v.action
        })
    df = pd.DataFrame(rows)
    df.to_csv(filename, index=False)
    click.echo(f"CSV raporu oluşturuldu: {filename}")
    session.close()

@click.command("generate-report")
@click.argument("filename")
def generate_report(filename):
    session = SessionLocal()
    vulns = session.query(Vulnerability).all()
    c = canvas.Canvas(filename, pagesize=letter)
    width, height = letter
    y = height - 50
    c.setFont("Helvetica", 12)
    c.drawString(50, y, "Zafiyet Raporu")
    y -= 30
    for v in vulns:
        line = f"[{v.id}] {v.name} | Risk={v.risk} | Status={v.status} | Host={v.host_id} | Action={v.action}"
        c.drawString(50, y, line)
        y -= 20
        if y < 50:
            c.showPage()
            y = height - 50
            c.setFont("Helvetica", 12)
    c.save()
    click.echo(f"PDF raporu oluşturuldu: {filename}")
    session.close()
