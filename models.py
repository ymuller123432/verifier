from datetime import datetime
from extensions import db

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="operator")  # admin|operator
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class BulkTask(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    creator = db.relationship("User", backref="bulk_tasks")

    status = db.Column(db.String(20), default="queued")  # queued|running|done|failed
    total = db.Column(db.Integer, default=0)
    processed = db.Column(db.Integer, default=0)
    error = db.Column(db.Text, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    finished_at = db.Column(db.DateTime, nullable=True)

class BulkResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey("bulk_task.id"), nullable=False)
    task = db.relationship("BulkTask", backref="results")

    email = db.Column(db.String(320), nullable=False)
    status = db.Column(db.String(30), nullable=False)   # valid|invalid|disposable|role|no_mx|unknown
    reason = db.Column(db.String(255), nullable=True)
