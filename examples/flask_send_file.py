from flask import Flask, request, send_file

app = Flask(__name__)


@app.route("/")
def direct():
    # bad — request.args.get() result passed directly to send_file()
    return send_file(request.args.get("path"))


@app.route("/local")
def local_var():
    # bad — request-controlled value assigned to a local, then passed
    path = request.args.get("path")
    return send_file(path)


@app.route("/form")
def form_var():
    # bad — request.form.get() instead of request.args.get()
    return send_file(request.form.get("path"))


@app.route("/values")
def values_var():
    # bad — request.values.get()
    return send_file(request.values.get("path"))


@app.route("/safe")
def safe():
    # okay — hardcoded path
    return send_file("/etc/hostname")


@app.route("/safe-join")
def safe_join():
    # okay — uses a sanitised path (not a request accessor pattern)
    import os

    base = "/var/data"
    rel = "report.txt"
    return send_file(os.path.join(base, rel))
