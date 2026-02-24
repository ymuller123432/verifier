# Internal Email Verifier (Flask + Postgres + Redis RQ)

This is an internal, admin-gated email verifier for permitted lists:
- Single verify: syntax + disposable + role + MX
- Bulk CSV/TXT upload: background worker (RQ) + export results CSV
- Admin-only: user management (admin can add an operator account for your friend)

## Local Run (optional)
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

export SECRET_KEY="dev"
export DATABASE_URL="sqlite:///local.db"
export REDIS_URL="redis://localhost:6379/0"

python app.py
python worker.py
```

## Deploy to Heroku (GitHub deploy)
High-level:
1) Push this repo to GitHub
2) Create a Heroku app and connect it to your GitHub repo
3) Add Postgres + Redis add-ons
4) Set config vars (SECRET_KEY, ADMIN_EMAIL, ADMIN_PASSWORD)
5) Scale web + worker

### Required config vars
- SECRET_KEY
- ADMIN_EMAIL (initial admin login)
- ADMIN_PASSWORD (initial admin password)

### Procfile
- release: python release.py
- web: gunicorn app:app
- worker: python worker.py

The release step creates tables and (optionally) creates the initial admin.

### After deploy
Open the app URL, log in with ADMIN_EMAIL/ADMIN_PASSWORD, then create an operator for your friend:
`/admin/users`
