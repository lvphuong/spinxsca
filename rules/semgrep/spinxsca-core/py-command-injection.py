import os
import subprocess

from flask import request


def a():
    host = request.args.get("host", "")
    # ruleid: py-command-injection
    subprocess.check_output("ping -c 1 " + host, shell=True)


def b():
    # ruleid: py-command-injection
    os.system("nslookup " + request.form["domain"])


def c():
    host = request.args.get("host", "")
    # ok: py-command-injection
    subprocess.check_output(["ping", "-c", "1", host])


def d():
    # ok: py-command-injection
    os.system("uptime")
