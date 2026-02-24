import csv
import io
import os
import ssl

from flask import Flask, render_template, request, redirect, url_for, flash, send_file, abort
from flask_login import login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

import redis
from rq import Queue

from config import Config
from extensions import db, login_manager
from models import User, BulkTask, BulkResult
from verify import verify_quick


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    login_manager.init_app(app)

    # (Optional) remove Flask-Login default "Please log in..." message
    login_manager.login_message = None
    login_manager.needs_refresh_message = None

    # Redis queue (Heroku KVS may use self-signed certs on rediss://)
    redis_url = app.config["REDIS_URL"]
    redis_kwargs = {}
    if redis_url.startswith("rediss://"):
        redis_kwargs["ssl_cert_reqs"] = ssl.CERT_NONE

    r = redis.from_url(redis_url, **redis_kwargs)
    q = Queue("bulk", connection=r)

    class LoginUser(UserMixin):
        def __init__(self, u: User):
            self.id = u.id
            self.email = u.email
            self.role = u.role
            self._active = bool(u.is_active)

        def get_user(self):
            return db.session.get(User, int(self.id))

        def is_active(self):
            return self._active

    @login_manager.user_loader
    def load_user(user_id):
        u = db.session.get(User, int(user_id))
        return LoginUser(u) if u and u.is_active else None

    def require_admin():
        if not getattr(current_user, "role", None) == "admin":
            abort(403)

    # ---------- AUTH ----------
    @app.get("/login")
    def login_page():
        return render_template("login.html")

    @app.post("/login")
    def login_post():
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        u = User.query.filter_by(email=email, is_active=True).first()
        if not u or not check_password_hash(u.password_hash, password):
            flash("Invalid login", "danger")
            return redirect(url_for("login_page"))
        login_user(LoginUser(u))
        return redirect(url_for("dashboard"))

    @app.get("/logout")
    @login_required
    def logout():
        logout_user()
        return redirect(url_for("login_page"))

    # ---------- DASHBOARD ----------
    @app.get("/")
    @login_required
    def dashboard():
        recent_tasks = BulkTask.query.order_by(BulkTask.created_at.desc()).limit(15).all()
        return render_template("dashboard.html", tasks=recent_tasks)

    # Single verify (web)
    @app.post("/verify")
    @login_required
    def verify_one():
        email = request.form.get("email", "")
        result = verify_quick(email)
        shown = result.get("email", email)
        flash(f"{shown} → {result['status']} ({result.get('reason','')})", "info")
        return redirect(url_for("dashboard"))

    # ---------- BULK ----------
    @app.get("/bulk/upload")
    @login_required
    def bulk_upload_page():
        return render_template("bulk_upload.html")

    @app.post("/bulk/upload")
    @login_required
    def bulk_upload_post():
        f = request.files.get("file")
        if not f:
            flash("Upload a CSV or TXT file", "warning")
            return redirect(url_for("bulk_upload_page"))

        filename = (f.filename or "").lower()
        content = f.read().decode("utf-8", errors="ignore")

        emails = []

        # Support .txt (one email per line) and .csv (first column emails)
        if filename.endswith(".txt"):
            for line in content.splitlines():
                line = line.strip()
                if line:
                    emails.append(line)
        else:
            reader = csv.reader(io.StringIO(content))
            for row in reader:
                if row and row[0].strip():
                    emails.append(row[0].strip())

        task = BulkTask(
            created_by=current_user.get_user().id,
            status="queued",
            total=len(emails),
            processed=0
        )
        db.session.add(task)
        db.session.commit()

        from tasks import process_bulk_task
        q.enqueue(process_bulk_task, task.id, emails)

        flash(f"Bulk task queued: #{task.id}", "success")
        return redirect(url_for("bulk_task_view", task_id=task.id))

    @app.get("/bulk/<int:task_id>")
    @login_required
    def bulk_task_view(task_id):
        task = db.session.get(BulkTask, task_id)
        if not task:
            abort(404)
        results = BulkResult.query.filter_by(task_id=task_id).limit(250).all()
        return render_template("bulk_task.html", task=task, results=results)

    @app.get("/bulk/<int:task_id>/export.<fmt>")
    @login_required
    def bulk_export(task_id, fmt):
        task = db.session.get(BulkTask, task_id)
        if not task:
            abort(404)

        fmt = (fmt or "csv").lower()
        if fmt not in {"csv", "txt"}:
            abort(400)

        output = io.StringIO()

        if fmt == "csv":
            w = csv.writer(output)
            w.writerow(["email", "status", "reason"])
            for r in BulkResult.query.filter_by(task_id=task_id).yield_per(1000):
                w.writerow([r.email, r.status, r.reason or ""])

            data = output.getvalue().encode("utf-8")
            mem = io.BytesIO(data)
            mem.seek(0)
            return send_file(
                mem,
                mimetype="text/csv",
                as_attachment=True,
                download_name=f"bulk_task_{task_id}.csv",
            )

        # TXT export: tab-separated for readability
        output.write("email\tstatus\treason\n")
        for r in BulkResult.query.filter_by(task_id=task_id).yield_per(1000):
            reason = (r.reason or "").replace("\n", " ").replace("\t", " ")
            output.write(f"{r.email}\t{r.status}\t{reason}\n")

        data = output.getvalue().encode("utf-8")
        mem = io.BytesIO(data)
        mem.seek(0)
        return send_file(
            mem,
            mimetype="text/plain",
            as_attachment=True,
            download_name=f"bulk_task_{task_id}.txt",
        )

    # ---------- USERS (Admin only) ----------
    @app.get("/admin/users")
    @login_required
    def users_page():
        require_admin()
        users = User.query.order_by(User.created_at.desc()).all()
        return render_template("users.html", users=users)

    @app.post("/admin/users/create")
    @login_required
    def users_create():
        require_admin()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()
        role = (request.form.get("role", "operator") or "operator").strip().lower()

        if role not in {"admin", "operator"}:
            role = "operator"

        if not email or not password:
            flash("Email + password required", "warning")
            return redirect(url_for("users_page"))

        if User.query.filter_by(email=email).first():
            flash("User already exists", "danger")
            return redirect(url_for("users_page"))

        u = User(email=email, password_hash=generate_password_hash(password), role=role)
        db.session.add(u)
        db.session.commit()
        flash("User created", "success")
        return redirect(url_for("users_page"))

    # ---------- CLI helpers ----------
    @app.cli.command("create-admin")
    def _cli_create_admin():
        """Create an admin user using env vars ADMIN_EMAIL and ADMIN_PASSWORD."""
        email = os.getenv("ADMIN_EMAIL", "").strip().lower()
        password = os.getenv("ADMIN_PASSWORD", "").strip()
        if not email or not password:
            print("Set ADMIN_EMAIL and ADMIN_PASSWORD then re-run.")
            return
        with app.app_context():
            existing = User.query.filter_by(email=email).first()
            if existing:
                print("Admin already exists:", email)
                return
            u = User(email=email, password_hash=generate_password_hash(password), role="admin")
            db.session.add(u)
            db.session.commit()
            print("Created admin:", email)

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=True)