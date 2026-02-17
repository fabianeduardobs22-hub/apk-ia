from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from database import Base


class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(Integer, primary_key=True)
    name = Column(String(120), unique=True, nullable=False)
    status = Column(String(30), default="active", nullable=False)
    plan = Column(String(30), default="enterprise", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True)
    name = Column(String(50), unique=True, nullable=False)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    password = Column(String(255), nullable=False)
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=False)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)

    role = relationship("Role")
    tenant = relationship("Tenant")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=False)
    action = Column(String(255), nullable=False)
    details = Column("metadata", Text, default="{}", nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    previous_hash = Column(String(128), nullable=False)
    current_hash = Column(String(128), nullable=False)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    severity = Column(String(16), nullable=False)
    message = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
