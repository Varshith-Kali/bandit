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
client. When the path comes from ``request.args``, ``request.form``, or
``request.values`` without validation, an attacker can traverse the
filesystem and read arbitrary files (CWE-22).

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

Simple local-variable assignments are followed::

    path = request.args.get("path")  # tainted
    return send_file(path)           # flagged

This analysis is intentionally shallow. Known blind spots:

- reassignment of the variable after the ``send_file()`` call site
- assignments inside branches or loops (only the nearest preceding
  simple assignment is considered)
- tuple unpacking, e.g. ``path, _ = request.args.get("path"), None``
- the path arriving as a function parameter or returned from another
  function (no interprocedural tracking)

:Example:

.. code-block:: none

    >> Issue: [B2XX:flask_send_file] Flask send_file() called with a
       request-controlled path
       Severity: Medium   Confidence: Medium
       CWE: CWE-22 (https://cwe.mitre.org/data/definitions/22.html)
       Location: examples/flask_send_file.py:10
    9
    10    return send_file(request.args.get("path"))

.. seealso::

 - https://flask.palletsprojects.com/en/stable/api/#flask.send_file
 .. https://cwe.mitre.org/data/definitions/22.html

"""  # noqa: E501
import ast

import bandit
from bandit.core import issue
from bandit.core import test_properties as test

# Request object accessors that carry client-controlled data
_REQUEST_ACCESSORS = frozenset(["args", "form", "values"])

# Qualified names under which Flask exposes send_file()
_SEND_FILE_NAMES = frozenset(["flask.send_file", "flask.helpers.send_file"])


def _dotted_parts(node):
    """Return the dotted parts of a Name/Attribute chain, else None."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    parts.reverse()
    return parts


def _import_bindings(root):
    """Collect local names bound to ``flask`` or ``flask.request``.

    Returns a tuple of (request_names, flask_names) where request_names
    holds names bound directly to ``flask.request`` (e.g. ``request``,
    ``req`` from ``from flask import request as req``) and flask_names
    holds names bound to the ``flask`` module itself (e.g. ``flask``,
    ``f`` from ``import flask as f``).
    """
    request_names = set()
    flask_names = set()
    for child in ast.walk(root):
        if isinstance(child, ast.ImportFrom) and child.module == "flask":
            for alias in child.names:
                if alias.name == "request":
                    request_names.add(alias.asname or alias.name)
        elif isinstance(child, ast.Import):
            for alias in child.names:
                if alias.name == "flask":
                    flask_names.add(alias.asname or alias.name)
    return request_names, flask_names


def _is_request_controlled(expr, request_names, flask_names):
    """Check if an expression reads client data from Flask's request."""
    # Unwrap calls and subscripts: request.args.get("x"),
    # request.form["x"], ...
    node = expr
    while isinstance(node, (ast.Call, ast.Subscript)):
        if isinstance(node, ast.Call):
            node = node.func
        else:
            node = node.value
    parts = _dotted_parts(node)
    if not parts or len(parts) < 2:
        return False
    if parts[0] in request_names:
        accessor = parts[1]
    elif parts[0] in flask_names and len(parts) > 2 and parts[1] == "request":
        accessor = parts[2]
    elif parts[0] == "request" and not request_names:
        # Fallback: a bare "request" name with no visible Flask import
        # binding (e.g. the import lives in another module).
        accessor = parts[1]
    else:
        return False
    return accessor in _REQUEST_ACCESSORS


def _tainted_assignment(name, scope, call_lineno, request_names, flask_names):
    """Check the nearest preceding simple assignment for request data."""
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
        return False
    return _is_request_controlled(assigned.value, request_names, flask_names)


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
    request_names, flask_names = _import_bindings(root)

    if _is_request_controlled(path_arg, request_names, flask_names):
        flagged = True
    elif isinstance(path_arg, ast.Name):
        scope = node
        while not isinstance(
            scope, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            scope = scope._bandit_parent
        flagged = _tainted_assignment(
            path_arg.id, scope, node.lineno, request_names, flask_names
        )
    else:
        flagged = False

    if flagged:
        return bandit.Issue(
            severity=bandit.MEDIUM,
            confidence=bandit.MEDIUM,
            cwe=issue.Cwe.PATH_TRAVERSAL,
            text="Flask send_file() called with a request-controlled "
            "path, which may allow path traversal and arbitrary file "
            "read.",
        )
