from flask import Flask, request, send_file

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


@app.route("/ok1")
def ok_hardcoded():
    # okay: hardcoded path is not request-controlled
    return send_file("/srv/files/report.pdf")


@app.route("/ok2")
def ok_other_kwarg():
    # okay: request data only selects the mimetype, not the file
    return send_file("/srv/files/report.pdf", mimetype=request.args.get("t"))
