# SPDX-License-Identifier: Apache-2.0
r"""
=======================================================
B2XX: Test for Flask send_file() path traversal
=======================================================

.. note::
   ``B2XX`` is a placeholder identifier. Bandit test IDs are grouped by
   category (B1xx, B2xx, B6xx, ...) and assigned by the bandit maintainers;
   the final ID for this check is left for them to allocate.

This plugin flags Flask ``send_file()`` calls whose path argument is
controlled by client request data.

``send_file(path_or_file)`` reads a file from disk and streams it to the
client. When the path comes from ``request.args``, ``request.form``,
``request.values``, ``request.cookies``, ``request.headers``, or the JSON
body (``request.json`` / ``request.get_json()``) without validation, an
attacker can traverse the filesystem and read arbitrary files (CWE-22).

Only the path argument is examined: the first positional argument, or the
``path_or_file=`` keyword form. Other arguments do not choose which file is
read and are never flagged, e.g. ``send_file("report.pdf",
mimetype=request.args.get("t"))`` is safe.

Request accessors are recognized through the file's import bindings::

    from flask import request            # request.args.get("path")
    from flask import request as req     # req.form.get("path")
    import flask                         # flask.request.args.get("path")

When no Flask import binding is visible for a bare ``request`` name (for
example the import lives in another module), the check falls back to
matching the name ``request`` directly. Objects other than Flask's request
that expose ``.args.get`` style accessors (e.g. argparse namespaces) can
therefore still be flagged; treat such findings with suspicion.

Taint is followed through common string composition, since paths are
rarely passed verbatim::

    send_file(f"/srv/files/{request.args['path']}")      # flagged
    send_file("/srv/files/" + request.args["path"])      # flagged
    send_file(os.path.join(BASE, request.args["path"]))  # flagged
    path = request.args.get("path")                      # tainted
    return send_file(path)                               # flagged

Known sanitizers are respected: ``safe_join`` and ``secure_filename``
(under any import alias) neutralize traversal, so
``send_file(safe_join(BASE, request.args["path"]))`` is not flagged.

This analysis is intentionally shallow. Known blind spots:

- reassignment of the variable after the ``send_file()`` call site
- assignments inside branches or loops (only the nearest preceding
  simple assignment is considered)
- tuple unpacking, e.g. ``path, _ = request.args.get("path"), None``
- the path arriving as a function parameter or returned from another
  function (no interprocedural tracking)
- ``request.files`` / ``request.stream`` / ``request.data`` are not
  treated as path sources: they are file-like or bytes objects, so e.g.
  ``send_file(request.files["f"])`` (streaming an upload) is safe; only
  the uploaded ``filename`` attribute is flagged

:Example:

.. code-block:: none

    >> Issue: [B2XX:flask_send_file] Flask send_file() called with a
       request-controlled path
       Severity: Medium   Confidence: Medium
       CWE: CWE-22 (https://cwe.mitre.org/data/definitions/22.html)
       Location: examples/flask_send_file.py:13
    12
    13    return send_file(request.args.get("path"))

.. seealso::

 - https://flask.palletsprojects.com/en/stable/api/#flask.send_file
 - https://cwe.mitre.org/data/definitions/22.html

"""  # noqa: E501
import ast

import bandit
from bandit.core import issue
from bandit.core import test_properties as test

# Request object accessors that carry client-controlled path data.
# request.files / request.stream / request.data are intentionally absent:
# they are file-like or bytes objects, not path strings (the uploaded
# filename is still caught via the "files" special case below).
_REQUEST_ACCESSORS = frozenset(
    ["args", "form", "values", "cookies", "headers", "json", "get_json"]
)

# Functions that neutralize path traversal; taint inside their arguments
# is not propagated.
_SANITIZER_FUNCS = frozenset(["safe_join", "secure_filename"])

# Modules the sanitizers are imported from.
_WERKZEUG_MODULES = frozenset(
    ["werkzeug", "werkzeug.utils", "werkzeug.security"]
)

# Qualified names under which Flask exposes send_file().
_SEND_FILE_NAMES = frozenset(["flask.send_file", "flask.helpers.send_file"])


def _dotted_parts(node):
    """Return the dotted parts of a Name/Attribute chain, else None.

    Calls and subscripts in the middle of the chain (e.g. the
    ``get_json()`` in ``request.get_json().get("p")``) are skipped over.
    """
    parts = []
    while True:
        while isinstance(node, (ast.Call, ast.Subscript)):
            if isinstance(node, ast.Call):
                node = node.func
            else:
                node = node.value
        if not isinstance(node, ast.Attribute):
            break
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    parts.reverse()
    return parts


def _import_bindings(root):
    """Collect local names bound to ``flask``, ``flask.request`` and the
    path sanitizers.

    Returns a tuple of (request_names, flask_names, sanitizer_names,
    werkzeug_names) where request_names holds names bound directly to
    ``flask.request``, flask_names holds names bound to the ``flask``
    module itself, sanitizer_names holds names bound to ``safe_join`` /
    ``secure_filename`` imported from werkzeug, and werkzeug_names holds
    names bound to the ``werkzeug`` package (for ``werkzeug.utils.…``
    style calls).
    """
    request_names = set()
    flask_names = set()
    sanitizer_names = set()
    werkzeug_names = set()
    for child in ast.walk(root):
        if isinstance(child, ast.ImportFrom):
            if child.module == "flask":
                for alias in child.names:
                    if alias.name == "request":
                        request_names.add(alias.asname or alias.name)
            elif child.module in _WERKZEUG_MODULES:
                for alias in child.names:
                    if alias.name in _SANITIZER_FUNCS:
                        sanitizer_names.add(alias.asname or alias.name)
        elif isinstance(child, ast.Import):
            for alias in child.names:
                if alias.name == "flask":
                    flask_names.add(alias.asname or alias.name)
                if alias.name == "werkzeug" or alias.name.startswith(
                    "werkzeug."
                ):
                    bound = (alias.asname or alias.name).split(".")[0]
                    werkzeug_names.add(bound)
    return request_names, flask_names, sanitizer_names, werkzeug_names


def _is_request_controlled(expr, request_names, flask_names):
    """Check if an expression reads client data from Flask's request."""
    # _dotted_parts skips over calls and subscripts, so
    # request.args.get("x"), request.form["x"],
    # request.get_json().get("x"), ... all reduce to a dotted chain.
    parts = _dotted_parts(expr)
    if not parts or len(parts) < 2:
        return False
    if parts[0] in request_names:
        rest = parts[1:]
    elif parts[0] in flask_names and len(parts) > 2 and parts[1] == "request":
        rest = parts[2:]
    elif parts[0] == "request" and not request_names:
        # Fallback: a bare "request" name with no visible Flask import
        # binding (e.g. the import lives in another module).
        rest = parts[1:]
    else:
        return False
    accessor = rest[0]
    if accessor == "files":
        # request.files["f"] is a FileStorage, safe to stream; only the
        # client-controlled uploaded filename is a traversal vector.
        return "filename" in rest[1:]
    return accessor in _REQUEST_ACCESSORS


def _is_sanitizer_call(func_node, sanitizer_names, werkzeug_names):
    """Check if a call target is a known path sanitizer."""
    parts = _dotted_parts(func_node)
    if not parts:
        return False
    if len(parts) == 1:
        return parts[0] in sanitizer_names
    return parts[-1] in _SANITIZER_FUNCS and parts[0] in werkzeug_names


def _resolve_assignment(name, scope, call_lineno):
    """Return the value of the nearest preceding simple assignment to
    ``name``, or None when there is none."""
    assigned = None
    for child in ast.walk(scope):
        if isinstance(child, ast.Assign):
            targets = child.targets
        elif isinstance(child, ast.AnnAssign):
            targets = [child.target]
        else:
            continue
        if child.lineno >= call_lineno:
            continue
        if any(
            isinstance(target, ast.Name) and target.id == name
            for target in targets
        ):
            if assigned is None or child.lineno > assigned.lineno:
                assigned = child
    if assigned is None:
        return None
    return assigned.value


def _is_tainted(expr, bindings, resolve, _seen=None):
    """Recursively check whether an expression derives from request data.

    Follows taint through string composition (``+``, f-strings,
    ``os.path.join`` and similar calls) but not through known sanitizers
    (``safe_join``, ``secure_filename``). ``resolve`` maps a variable name
    to its assigned value for simple local-variable indirection.
    """
    request_names, flask_names, sanitizer_names, werkzeug_names = bindings
    if _is_request_controlled(expr, request_names, flask_names):
        return True
    if isinstance(expr, ast.Name):
        if _seen is None:
            _seen = set()
        if expr.id in _seen:
            return False
        _seen.add(expr.id)
        value = resolve(expr.id)
        return value is not None and _is_tainted(
            value, bindings, resolve, _seen
        )
    if isinstance(expr, ast.BinOp):
        return _is_tainted(expr.left, bindings, resolve, _seen) or _is_tainted(
            expr.right, bindings, resolve, _seen
        )
    if isinstance(expr, ast.JoinedStr):
        return any(
            _is_tainted(
                val.value if isinstance(val, ast.FormattedValue) else val,
                bindings,
                resolve,
                _seen,
            )
            for val in expr.values
        )
    if isinstance(expr, ast.IfExp):
        return _is_tainted(expr.body, bindings, resolve, _seen) or _is_tainted(
            expr.orelse, bindings, resolve, _seen
        )
    if isinstance(expr, ast.Call):
        if _is_sanitizer_call(expr.func, sanitizer_names, werkzeug_names):
            return False
        return any(
            _is_tainted(arg, bindings, resolve, _seen) for arg in expr.args
        ) or any(
            _is_tainted(kw.value, bindings, resolve, _seen)
            for kw in expr.keywords
        )
    return False


def _path_argument(node):
    """Return the path argument of a send_file() call, if identifiable.

    Only the first positional argument and the ``path_or_file=`` keyword
    form are considered; any other keyword (e.g. ``mimetype=``) never
    selects the file and is ignored.
    """
    if node.args:
        return node.args[0]
    for keyword in node.keywords:
        if keyword.arg == "path_or_file":
            return keyword.value
    return None


# Placeholder ID: the final test ID is assigned by the bandit maintainers.
@test.test_id("B2XX")
@test.checks("Call")
def flask_send_file(context):
    if context.call_function_name_qual not in _SEND_FILE_NAMES:
        return
    node = context.node
    path_arg = _path_argument(node)
    if path_arg is None:
        return

    # Collect import bindings from the module root. _bandit_parent is set
    # by the node visitor on every node except the module root itself.
    root = node
    while hasattr(root, "_bandit_parent"):
        root = root._bandit_parent
    bindings = _import_bindings(root)

    # Innermost enclosing scope for resolving local variable indirection.
    scope = node
    while not isinstance(
        scope, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef)
    ):
        scope = scope._bandit_parent

    def resolve(name):
        return _resolve_assignment(name, scope, node.lineno)

    if _is_tainted(path_arg, bindings, resolve):
        return bandit.Issue(
            severity=bandit.MEDIUM,
            confidence=bandit.MEDIUM,
            cwe=issue.Cwe.PATH_TRAVERSAL,
            text="Flask send_file() called with a request-controlled "
            "path, which may allow path traversal and arbitrary file "
            "read.",
        )
