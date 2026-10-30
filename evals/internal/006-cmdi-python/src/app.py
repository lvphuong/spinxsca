import os
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    # Vulnerable: shell command built from request input.
    output = subprocess.check_output("ping -c 1 " + host, shell=True)
    return output


@app.route("/lookup")
def lookup():
    domain = request.args.get("domain", "")
    os.system("nslookup " + domain)
    return "ok"


@app.route("/ping-safe")
def ping_safe():
    host = request.args.get("host", "")
    output = subprocess.check_output(["ping", "-c", "1", host])
    return output
