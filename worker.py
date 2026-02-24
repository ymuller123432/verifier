import os
import ssl
import redis
from rq import Worker, Queue, Connection

from app import create_app
from extensions import db

listen = ["bulk"]

def get_redis_url() -> str:
    return os.getenv("REDIS_URL") or os.getenv("REDIS_TLS_URL") or "redis://localhost:6379/0"

def main():
    app = create_app()
    with app.app_context():
        db.engine.connect().close()

        url = get_redis_url()
        kwargs = {}
        if url.startswith("rediss://"):
            kwargs["ssl_cert_reqs"] = ssl.CERT_NONE

        conn = redis.from_url(url, **kwargs)
        with Connection(conn):
            worker = Worker([Queue(name) for name in listen])
            worker.work(with_scheduler=False)

if __name__ == "__main__":
    main()