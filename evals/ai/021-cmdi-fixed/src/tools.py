import re
import subprocess

from flask import Flask, request

app = Flask(__name__)
HOST = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if not HOST.match(host):
        return "invalid host", 400
    return subprocess.check_output(["ping", "-c", "1", host], text=True)
