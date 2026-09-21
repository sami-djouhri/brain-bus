"""Lerner-Routen, in main.py einbinden via:

    from app.routes_learner import router as learner_router
    app.include_router(learner_router)
"""
from fastapi import APIRouter, BackgroundTasks, HTTPException

from app import learner

router = APIRouter(prefix="/api/learner", tags=["learner"])


@router.post("/run")
def learner_run(background: BackgroundTasks):
    """Stößt Lernlauf im Hintergrund an. LLM-Call kann 60-90s dauern."""
    background.add_task(learner.run)
    return {"status": "scheduled"}


@router.get("/last")
def learner_last():
    rep = learner.get_last()
    if rep is None:
        raise HTTPException(status_code=404, detail="Noch kein Lauf vorhanden.")
    return rep
