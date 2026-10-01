# Intentionally insecure sample - DO NOT RUN. Used as a scanner test fixture.
import os
import pickle
import sqlite3
import subprocess

import yaml

DB_PASSWORD = "SuperSecret123"


def run(user_input, blob, data, uid, cmd):
    eval(user_input)
    os.system("ping " + user_input)
    subprocess.call(cmd, shell=True)
    pickle.loads(blob)
    yaml.load(data)
    cur = sqlite3.connect("app.db").cursor()
    cur.execute(f"SELECT * FROM users WHERE id = {uid}")
    try:
        risky()
    except:
        print("error")
    try:
        risky()
    except Exception:
        pass


def risky():
    raise RuntimeError
