import os
from pathlib import Path

from flask import Flask, request, send_file
from werkzeug.utils import safe_join, secure_filename

app = Flask(__name__)


@app.route("/bad1")
def bad_direct():
    # bad: path comes straight from the query string
    return send_file(request.args.get("path"))


@app.route("/bad2")
def bad_form():
    # bad: path comes from form data
    return send_file(request.form["path"])


@app.route("/bad3")
def bad_keyword():
    # bad: path_or_file keyword is request-controlled
    return send_file(path_or_file=request.values.get("path"))


@app.route("/bad4")
def bad_local_var():
    # bad: request-controlled value assigned to a local variable
    path = request.args.get("path")
    return send_file(path)


@app.route("/bad5")
def bad_fstring():
    # bad: f-string embedding request-controlled data
    return send_file(f"/srv/files/{request.args.get('path')}")


@app.route("/bad6")
def bad_concat():
    # bad: string concatenation with request-controlled data
    return send_file("/srv/files/" + request.args.get("path"))


@app.route("/bad7")
def bad_path_join():
    # bad: os.path.join does not sanitize against traversal
    return send_file(os.path.join("/srv/files", request.args.get("path")))


@app.route("/bad8")
def bad_pathlib():
    # bad: pathlib / operator with request-controlled part
    return send_file(Path("/srv/files") / request.args.get("path"))


@app.route("/bad9")
def bad_cookies():
    # bad: cookies are client-controlled
    return send_file(request.cookies.get("path"))


@app.route("/bad10")
def bad_headers():
    # bad: headers are client-controlled
    return send_file(request.headers["X-Filename"])


@app.route("/bad11")
def bad_json():
    # bad: JSON body is client-controlled
    return send_file(request.get_json().get("path"))


@app.route("/bad12")
def bad_wrapped():
    # bad: wrapping in str() does not sanitize
    return send_file(str(request.args.get("path")))


@app.route("/bad13")
def bad_var_concat():
    # bad: tainted variable composed into a path
    filename = request.args.get("path")
    return send_file("/srv/files/" + filename)


@app.route("/ok1")
def ok_hardcoded():
    # okay: hardcoded path is not request-controlled
    return send_file("/srv/files/report.pdf")


@app.route("/ok2")
def ok_other_kwarg():
    # okay: request data only selects the mimetype, not the file
    return send_file("/srv/files/report.pdf", mimetype=request.args.get("t"))


@app.route("/ok3")
def ok_safe_join():
    # okay: safe_join neutralizes traversal
    return send_file(safe_join("/srv/files", request.args.get("path")))


@app.route("/ok4")
def ok_secure_filename():
    # okay: secure_filename strips path components
    return send_file(secure_filename(request.args.get("path")))


@app.route("/ok5")
def ok_literal_traversal():
    # okay: hardcoded literal is not request-controlled
    # (deterministic, not attacker-influenced)
    return send_file("../../etc/passwd")
