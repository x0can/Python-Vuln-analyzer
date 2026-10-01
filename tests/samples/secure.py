# Secure counterpart of vulnerable.py - should produce zero findings.
import ast
import json
import logging
import os
import sqlite3
import subprocess

import yaml

log = logging.getLogger(__name__)
DB_PASSWORD = os.environ.get("DB_PASSWORD")


def run(user_input, blob, data, uid, host):
    ast.literal_eval(user_input)
    subprocess.run(["ping", "-c", "1", host], check=True)
    json.loads(blob)
    yaml.safe_load(data)
    cur = sqlite3.connect("app.db").cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (uid,))
    try:
        risky()
    except RuntimeError as exc:
        log.error("risky failed: %s", exc)
        raise


def risky():
    raise RuntimeError
