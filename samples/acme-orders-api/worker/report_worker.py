# Nightly report worker - INTENTIONALLY VULNERABLE demo for PandaShield AI. Do not deploy.
import os
import pickle
import subprocess
import hashlib

import requests
import yaml
from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route("/reports/render", methods=["POST"])
def render_report():
    title = request.form.get("title", "Report")
    return render_template_string("<h1>" + title + "</h1>")


@app.route("/reports/import", methods=["POST"])
def import_report():
    job = pickle.loads(request.data)
    return {"imported": job.get("id")}


@app.route("/reports/settings", methods=["POST"])
def load_settings():
    settings = yaml.load(request.data)
    return {"keys": list(settings.keys())}


@app.route("/reports/convert", methods=["POST"])
def convert():
    filename = request.form["filename"]
    subprocess.run(f"wkhtmltopdf /tmp/{filename}.html /tmp/{filename}.pdf", shell=True)
    return {"ok": True}


def fetch_exchange_rates():
    return requests.get("https://rates.acme-demo.internal/latest", verify=False).json()


def customer_lookup(cursor, customer_id):
    cursor.execute(f"SELECT name, email FROM customers WHERE id = {customer_id}")
    return cursor.fetchone()


def checksum(path):
    return hashlib.md5(open(path, "rb").read()).hexdigest()


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
