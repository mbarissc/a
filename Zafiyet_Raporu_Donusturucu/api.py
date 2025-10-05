from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from db import SessionLocal
from models import Host, Vulnerability

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

# ---------------- HOSTS ----------------
@app.get("/hosts")
def list_hosts(db: Session = Depends(get_db)):
    return db.query(Host).all()

# ---------------- VULNERABILITIES ----------------
@app.get("/hosts/{host_id}/vulns")
def list_vulns(host_id: int, db: Session = Depends(get_db)):
    return db.query(Vulnerability).filter_by(host_id=host_id).all()

@app.put("/vulns/{vuln_id}")
def update_vuln(vuln_id: int, status: str, db: Session = Depends(get_db)):
    vuln = db.query(Vulnerability).get(vuln_id)
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
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
