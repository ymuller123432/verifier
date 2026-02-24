"""Heroku release-phase script.
- Creates tables if they don't exist.
- Optionally creates the initial admin user if ADMIN_EMAIL and ADMIN_PASSWORD are set.
"""
import os
from werkzeug.security import generate_password_hash

from app import create_app
from extensions import db
from models import User

def main():
    app = create_app()
    with app.app_context():
        db.create_all()

        email = (os.getenv("ADMIN_EMAIL") or "").strip().lower()
        password = (os.getenv("ADMIN_PASSWORD") or "").strip()
        if email and password:
            existing = User.query.filter_by(email=email).first()
            if not existing:
                u = User(email=email, password_hash=generate_password_hash(password), role="admin")
                db.session.add(u)
                db.session.commit()
                print("Created initial admin:", email)
            else:
                print("Admin already exists:", email)
        else:
            print("ADMIN_EMAIL/ADMIN_PASSWORD not set; skipping admin auto-create.")

if __name__ == "__main__":
    main()
