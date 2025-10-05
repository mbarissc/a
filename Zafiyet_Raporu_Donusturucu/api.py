from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from db import SessionLocal
from models import Host, Vulnerability, VulnerabilityHistory
from sqlalchemy import func
from datetime import datetime, timedelta

app = FastAPI(title="Nessus API")

# ---------------- CORS ----------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # test için herkese açıyoruz
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------- DB SESSION ----------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------- HOSTS ----------------
@app.get("/hosts")
def list_hosts(db: Session = Depends(get_db)):
    return db.query(Host).all()


# ---------------- COMPANIES (YENİ) ----------------
@app.get("/companies")
def get_companies(db: Session = Depends(get_db)):
    # Host tablosundaki benzersiz şirket isimlerini çek
    companies = db.query(Host.company).distinct().all()
    # Sonuçları düz bir liste olarak döndür: ["Company A", "Company B", ...]
    return [c[0] for c in companies if c[0]]


# ---------------- VULNERABILITIES ----------------
@app.get("/hosts/{host_id}/vulns")
def list_vulns_by_host(host_id: int, db: Session = Depends(get_db)):
    return db.query(Vulnerability).filter_by(host_id=host_id).all()


# Şirket adına göre zafiyetleri çeken yeni endpoint
@app.get("/companies/{company_name}/vulns")
def list_vulns_by_company(company_name: str, db: Session = Depends(get_db)):
    # Belirtilen şirkete ait tüm hostların ID'lerini bul
    host_ids = db.query(Host.id).filter(Host.company == company_name).subquery()

    # Bu hostlara ait tüm zafiyetleri çek
    vulns = db.query(Vulnerability).filter(Vulnerability.host_id.in_(host_ids)).all()
    return vulns


@app.put("/vulns/{vuln_id}")
def update_vuln(vuln_id: int, status: str, db: Session = Depends(get_db)):
    vuln = db.query(Vulnerability).get(vuln_id)
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    # History kaydı ekle
    if status in ['open', 'closed']:
        db.add(VulnerabilityHistory(vuln_id=vuln.id, status=status))

    vuln.status = status
    db.commit()
    db.refresh(vuln)
    return vuln


@app.delete("/vulns/{vuln_id}")
def delete_vuln(vuln_id: int, db: Session = Depends(get_db)):
    vuln = db.query(Vulnerability).get(vuln_id)
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    db.delete(vuln)
    db.commit()
    return {"message": "Deleted"}


@app.put("/vulns/{vuln_id}/action")
def set_vuln_action(vuln_id: int, action: str, db: Session = Depends(get_db)):
    vuln = db.query(Vulnerability).get(vuln_id)
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    vuln.action = action
    db.commit()
    db.refresh(vuln)
    return vuln


@app.get("/vulns/{vuln_id}/history")
def get_vuln_history(vuln_id: int, db: Session = Depends(get_db)):
    # Sadece 'open', 'closed' ve 'reopened' durumlarını çek
    history_entries = (
        db.query(VulnerabilityHistory)
        .filter(VulnerabilityHistory.vuln_id == vuln_id)
        .filter(VulnerabilityHistory.status.in_(['open', 'closed', 'reopened', 'reopen']))
        .order_by(VulnerabilityHistory.date)
        .all()
    )

    # ISO formatında tarih ve status döndür
    return [
        {"status": h.status, "date": h.date.isoformat()}
        for h in history_entries
    ]