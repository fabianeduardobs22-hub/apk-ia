# SENTINEL-X Enterprise SaaS Scaffold

## Run

```bash
cd sentinelx-enterprise/backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload
```

Open `http://localhost:8000`.

> Demo users via header `X-User`:
> - `root` (SUPER_ADMIN)
> - `acmeadmin` (TENANT_ADMIN)
> - `analyst` (SOC_ANALYST)

## Features connected

- RBAC multinivel y protección de endpoints
- Auditoría inmutable con hash encadenado
- Alertas realtime por WebSocket (web + móvil)
- Predicción temprana de amenazas
- Panel SUPER_ADMIN `/admin/tenants`
- Globe 3D en dashboard premium
