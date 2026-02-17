from datetime import datetime

from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi import Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ai_predictive import predict_attack_pattern
from audit import log_action
from auth import get_current_user
from database import Base, engine, get_db, SessionLocal
from models import Alert, Role, Tenant, User, AuditLog
from notifications import connect, disconnect, notify_tenant
from rbac import authorize

app = FastAPI(title="SENTINEL-X Enterprise SaaS")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


def seed_data() -> None:
    db = SessionLocal()
    try:
        if db.scalar(select(Role).limit(1)):
            return

        roles = [Role(name=name) for name in ["SUPER_ADMIN", "TENANT_ADMIN", "SOC_ANALYST", "READ_ONLY"]]
        db.add_all(roles)
        db.flush()

        tenant_root = Tenant(name="Global", plan="super")
        tenant_a = Tenant(name="Acme Corp")
        db.add_all([tenant_root, tenant_a])
        db.flush()

        users = [
            User(username="root", password="root", role_id=roles[0].id, tenant_id=tenant_root.id),
            User(username="acmeadmin", password="admin", role_id=roles[1].id, tenant_id=tenant_a.id),
            User(username="analyst", password="analyst", role_id=roles[2].id, tenant_id=tenant_a.id),
        ]
        db.add_all(users)
        db.commit()
    finally:
        db.close()


@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)
    seed_data()


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request, "now": datetime.utcnow().isoformat()})


@app.get("/health")
def health():
    return {"status": "ok", "service": "sentinelx-enterprise"}


@app.get("/admin/tenants")
def list_tenants(user=Depends(get_current_user), db: Session = Depends(get_db)):
    role_name = user.role.name
    if not authorize(role_name, "view") or role_name != "SUPER_ADMIN":
        raise HTTPException(status_code=403, detail="Forbidden")
    log_action(db, user.id, "admin_list_tenants")
    tenants = db.scalars(select(Tenant)).all()
    return [{"id": t.id, "name": t.name, "status": t.status, "plan": t.plan} for t in tenants]


@app.post("/alerts")
async def create_alert(payload: dict, user=Depends(get_current_user), db: Session = Depends(get_db)):
    if not authorize(user.role.name, "respond"):
        raise HTTPException(status_code=403, detail="Forbidden")

    alert = Alert(
        tenant_id=user.tenant_id,
        severity=payload.get("severity", "medium"),
        message=payload.get("message", "Potential anomaly detected"),
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)

    log_action(db, user.id, "create_alert", {"alert_id": alert.id, "severity": alert.severity})
    await notify_tenant(user.tenant_id, {"id": alert.id, "message": alert.message, "severity": alert.severity})
    return {"ok": True, "alert_id": alert.id}


@app.post("/predict")
def predict(payload: dict, user=Depends(get_current_user), db: Session = Depends(get_db)):
    if not authorize(user.role.name, "view"):
        raise HTTPException(status_code=403, detail="Forbidden")
    sequence = payload.get("sequence", [[0.1] * 10, [0.2] * 10, [0.5] * 10])
    result = predict_attack_pattern(sequence)
    log_action(db, user.id, "predict_attack_pattern", {"risk_score": result.risk_score})
    return {"risk_score": result.risk_score, "classification": result.classification}


@app.get("/audit")
def get_audit(user=Depends(get_current_user), db: Session = Depends(get_db)):
    if not authorize(user.role.name, "view_audit") and user.role.name != "SUPER_ADMIN":
        raise HTTPException(status_code=403, detail="Forbidden")
    rows = db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(100)).all()
    return [
        {
            "id": r.id,
            "user_id": r.user_id,
            "action": r.action,
            "metadata": r.details,
            "timestamp": r.timestamp.isoformat(),
            "hash": r.current_hash,
        }
        for r in rows
    ]


@app.websocket("/ws/{tenant_id}")
async def ws_alerts(websocket: WebSocket, tenant_id: int):
    await connect(tenant_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        disconnect(tenant_id, websocket)
