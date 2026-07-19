#
# SPDX-License-Identifier: Apache-2.0
r"""
======================================================
B905: Test for Flask send_file() with request-controlled path
======================================================

Flask's ``send_file()`` is commonly used to serve files to clients. When the
path argument is taken directly from request-controlled input (such as
``request.args.get(...)``, ``request.form.get(...)``, or
``request.values.get(...)``), an attacker can read arbitrary files from the
server — a classic path traversal / arbitrary file read vulnerability.

This pattern has been the root cause of multiple CVEs, including:

 - CVE-2025-6166 (Agent-Zero)
 - CVE-2022-31583
 - CVE-2022-31549
 - CVE-2022-31506

Two patterns are flagged (both narrow, AST-level — no interprocedural dataflow):

 1. ``send_file(request.args.get("path"))`` — the request accessor is the
    argument expression itself.
 2. ``path = request.args.get("path"); send_file(path)`` — the argument is a
    bare ``Name`` whose most recent assignment in the same function body is a
    request accessor.

:Example:

.. code-block:: none

    >> Issue: Flask send_file() called with a request-controlled path; this
    can lead to arbitrary file read / path traversal.
       Severity: Medium   Confidence: Medium
       CWE: CWE-22 (https://cwe.mitre.org/data/definitions/22.html)
       Location: examples/flask_send_file.py:7
    6  path = request.args.get("path")
    7  return send_file(path)

.. seealso::

 - https://flask.palletsprojects.com/en/stable/api/#flask.send_file
 - https://cwe.mitre.org/data/definitions/22.html

.. versionadded:: 1.9.0

"""  # noqa: E501
import ast

import bandit
from bandit.core import issue
from bandit.core import test_properties as test

# Request accessors that return user-controlled strings; if their result
# reaches send_file() the path is attacker-controlled.
_REQUEST_ACCESSOR_QUALS = (
    "request.args.get",
    "request.form.get",
    "request.values.get",
)


def _is_request_accessor_call(node: ast.AST) -> bool:
    """Return True if *node* is an AST Call to a known request accessor.

    Matches both ``request.args.get("path")`` and aliased imports like
    ``flask_request.args.get("path")`` (when the user did
    ``from flask import request as flask_request``); the check is on the
    trailing ``.args.get`` / ``.form.get`` / ``.values.get`` suffix.
    """
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if not isinstance(func, ast.Attribute):
        return False
    # func is something like `request.args.get` — walk the attribute chain
    # and reconstruct the dotted name.
    parts = []
    current = func
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    qual = ".".join(reversed(parts))
    return any(qual.endswith(accessor) for accessor in _REQUEST_ACCESSOR_QUALS)


def _contains_request_accessor(node: ast.AST) -> bool:
    """Walk *node* and return True if any sub-expression is a request
    accessor call (``request.args.get`` / ``request.form.get`` /
    ``request.values.get``)."""
    for child in ast.walk(node):
        if _is_request_accessor_call(child):
            return True
    return False


def _resolve_name_to_request_accessor(
    name_node: ast.Name, function_node: ast.AST | None
) -> bool:
    """Return True if *name_node*'s id is assigned from a request accessor
    somewhere earlier in *function_node*'s body.

    This is a deliberately narrow intra-function check — it only looks at
    top-level ``Assign`` statements in the enclosing function (no nested
    blocks, no interprocedural dataflow). False positives are avoided by
    only matching assignments where the RHS is itself a request accessor
    call; if the most recent assignment to the name is something else
    (e.g. a sanitised path), the name is treated as safe.
    """
    if function_node is None or not hasattr(function_node, "body"):
        return False
    target_id = name_node.id
    # Walk the function body in source order; track the last assignment
    # to the target name. We deliberately only look at direct ``Assign``
    # nodes in the function body (not nested blocks) to keep this a
    # narrow, conservative check — the goal is to catch the obvious
    # ``path = request.args.get(...); send_file(path)`` pattern, not to
    # implement a full dataflow analysis.
    last_assignment_was_accessor = False
    for stmt in ast.walk(function_node):
        if not isinstance(stmt, ast.Assign):
            continue
        for target in stmt.targets:
            if isinstance(target, ast.Name) and target.id == target_id:
                last_assignment_was_accessor = _contains_request_accessor(
                    stmt.value
                )  # noqa: E501
    return last_assignment_was_accessor


def _find_enclosing_function(call_node: ast.AST) -> ast.AST | None:
    """Walk the ``_bandit_parent`` chain set by bandit's node visitor to
    find the ``FunctionDef`` (or ``AsyncFunctionDef``) enclosing *call_node*.

    Returns ``None`` if the call is at module level or bandit hasn't set
    the parent chain (older versions / different visitor).
    """
    current = getattr(call_node, "_bandit_parent", None)
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return current
        current = getattr(current, "_bandit_parent", None)
    return None


@test.test_id("B905")
@test.checks("Call")
def flask_send_file_with_request_path(context):
    if not context.is_module_imported_like("flask"):
        return
    # Match send_file (also flask.send_file when called qualified).
    if not context.call_function_name_qual.endswith("send_file"):
        return
    # No arguments? Nothing to flag.
    if context.call_args_count == 0:
        return
    # Walk the raw AST of the call so we can inspect every argument
    # expression (positional + keyword) for a request-accessor sub-call.
    call_node = context.node
    if not isinstance(call_node, ast.Call):
        return
    # The enclosing function body, used to resolve bare-Name arguments
    # back to their most recent assignment (intra-function, no dataflow).
    function_node = _find_enclosing_function(call_node)
    for arg in list(call_node.args) + list(call_node.keywords):
        expr = arg.value if isinstance(arg, ast.keyword) else arg
        # Case 1: the argument expression itself contains a request accessor
        # (e.g. send_file(request.args.get("path"))).
        if _contains_request_accessor(expr):
            return bandit.Issue(
                severity=bandit.MEDIUM,
                confidence=bandit.MEDIUM,
                cwe=issue.Cwe.PATH_TRAVERSAL,
                text="Flask send_file() called with a request-controlled "
                "path; this can lead to arbitrary file read / path "
                "traversal. Sanitise or constrain the path before serving.",
                lineno=call_node.lineno,
            )
        # Case 2: the argument is a bare Name that was assigned from a
        # request accessor earlier in the same function body
        # (e.g. path = request.args.get("path"); send_file(path)).
        if isinstance(expr, ast.Name) and _resolve_name_to_request_accessor(
            expr, function_node
        ):
            return bandit.Issue(
                severity=bandit.MEDIUM,
                confidence=bandit.MEDIUM,
                cwe=issue.Cwe.PATH_TRAVERSAL,
                text="Flask send_file() called with a local variable "
                "assigned from a request accessor; this can lead to "
                "arbitrary file read / path traversal. Sanitise or "
                "constrain the path before serving.",
                lineno=call_node.lineno,
            )
