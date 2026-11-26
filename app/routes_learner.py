"""Lerner-Routen, in main.py einbinden via:

    from app.routes_learner import router as learner_router
    app.include_router(learner_router)
"""
from fastapi import APIRouter, HTTPException

from app import learner

router = APIRouter(prefix="/api/learner", tags=["learner"])

# Nur lesend. Den Lauf startet allein der Host-Cron (python -m app.cron_learner);
# ein POST /run ohne Auth haette jedem Prozess im Netz einen LLM-Lauf erlaubt.


@router.get("/last")
def learner_last():
    rep = learner.get_last()
    if rep is None:
        raise HTTPException(status_code=404, detail="Noch kein Lauf vorhanden.")
    return rep
