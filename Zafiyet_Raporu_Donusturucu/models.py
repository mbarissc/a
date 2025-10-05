from sqlalchemy import Column, Integer, String, Text, ForeignKey, TIMESTAMP
from sqlalchemy.orm import relationship
from datetime import datetime
from db import Base


class Host(Base):
    __tablename__ = "hosts"

    id = Column(Integer, primary_key=True)
    ip = Column(String(45))
    hostname = Column(String(255))
    os = Column(String(255))
    company = Column(String(255))
    created_at = Column(TIMESTAMP, default=datetime.utcnow)

    vulnerabilities = relationship("Vulnerability", back_populates="host", cascade="all, delete")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey("hosts.id"))
    cve = Column(String(255))
    risk = Column(String(50))
    protocol = Column(String(50))
    port = Column(String(50))
    name = Column(String(255))
    synopsis = Column(Text)
    solution = Column(Text)
    status = Column(String(50), default="open")
    action = Column(String(255), default="-")

    host = relationship("Host", back_populates="vulnerabilities")
    history = relationship("VulnerabilityHistory", back_populates="vuln", cascade="all, delete")


class VulnerabilityHistory(Base):
    __tablename__ = "vulnerability_history"

    id = Column(Integer, primary_key=True)
    vuln_id = Column(Integer, ForeignKey("vulnerabilities.id"))
    status = Column(String(50))
    date = Column(TIMESTAMP, default=datetime.utcnow)

    vuln = relationship("Vulnerability", back_populates="history")


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    role = Column(String(20), default="viewer")  # admin / analyst / viewer
    created_at = Column(TIMESTAMP, default=datetime.utcnow)


class VulnStatusHistory:
    pass