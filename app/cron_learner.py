"""CLI-Entry für Host-Cron: `docker exec brain-bus python -m app.cron_learner`."""
import json
import logging

from app.learner import run

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

if __name__ == "__main__":
    report = run()
    print(json.dumps({
        "rules_analyzed": report["rules_analyzed"],
        "suggestions": len(report.get("suggestions", [])),
        "duration_s": report.get("duration_s"),
    }))
