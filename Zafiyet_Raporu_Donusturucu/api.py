from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from db import SessionLocal
from models import Host, Vulnerability, VulnerabilityHistory

app = FastAPI(title="Nessus API")

# ---------------- CORS ----------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # test için herkese açıyoruz
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

# ---------------- COMPANIES ----------------
@app.get("/companies")
def list_companies(db: Session = Depends(get_db)):
    companies = db.query(Host.company).distinct().all()
    return [c[0] for c in companies if c[0]]

@app.get("/companies/{company_name}/vulns")
def get_vulns_by_company(company_name: str, db: Session = Depends(get_db)):
    hosts = db.query(Host).filter(Host.company == company_name).all()
    host_ids = [h.id for h in hosts]
    vulns = db.query(Vulnerability).filter(Vulnerability.host_id.in_(host_ids)).all()
    return vulns

# ---------------- VULNERABILITIES ----------------
@app.get("/hosts/{host_id}/vulns")
def list_vulns(host_id: int, db: Session = Depends(get_db)):
    return db.query(Vulnerability).filter_by(host_id=host_id).all()

@app.put("/vulns/{vuln_id}")
def update_vuln_status(vuln_id: int, status: str, db: Session = Depends(get_db)):
    vuln = db.query(Vulnerability).get(vuln_id)
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    vuln.status = status
    db.add(VulnerabilityHistory(vuln_id=vuln.id, status=status))
    db.commit()
    db.refresh(vuln)
    return vuln

@app.put("/vulns/{vuln_id}/score")
def set_vuln_score(vuln_id: int, score: int, db: Session = Depends(get_db)):
    vuln = db.query(Vulnerability).get(vuln_id)
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    vuln.score = score
    db.commit()
    db.refresh(vuln)
    return vuln

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
    history = db.query(VulnerabilityHistory).filter_by(vuln_id=vuln_id).order_by(VulnerabilityHistory.date).all()
    if not history:
        raise HTTPException(status_code=404, detail="History not found for this vulnerability")
    return history

@app.delete("/vulns/{vuln_id}")
def delete_vuln(vuln_id: int, db: Session = Depends(get_db)):
    vuln = db.query(Vulnerability).get(vuln_id)
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    db.delete(vuln)
    db.commit()
    return {"message": "Deleted"}