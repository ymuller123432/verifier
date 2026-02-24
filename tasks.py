from datetime import datetime
from extensions import db
from models import BulkTask, BulkResult
from verify import verify_quick

def process_bulk_task(task_id: int, emails: list[str]) -> None:
    task = db.session.get(BulkTask, task_id)
    if not task:
        return

    try:
        task.status = "running"
        task.total = len(emails)
        task.processed = 0
        db.session.commit()

        for i, em in enumerate(emails, start=1):
            result = verify_quick(em)
            db.session.add(BulkResult(
                task_id=task_id,
                email=(em or "").strip(),
                status=result["status"],
                reason=result.get("reason")
            ))
            task.processed = i

            # Commit in batches for stability.
            if i % 250 == 0:
                db.session.commit()

        task.status = "done"
        task.finished_at = datetime.utcnow()
        db.session.commit()

    except Exception as e:
        task.status = "failed"
        task.error = str(e)
        task.finished_at = datetime.utcnow()
        db.session.commit()
