"""The AKAC profile of the OpenID AuthZEN Authorization API 1.0 evaluation request (R-AZ, ADR-011).

The tenant is the enforcement point credential's tenant and is never read from the request.
"""
from .js import utf16_length
from .validation import valid_id

AUTHZEN_ACTIONS = ["read", "derive", "write_memory", "share", "export"]


def _plain(x):
    return isinstance(x, dict)


def _str(x):
    return isinstance(x, str)


def map_evaluation(tenant, e):
    """{"ok": True, "binding", "resource", "action", "purpose", "destination"?} or {"ok": False, "kind": "malformed"|"unsupported"}."""
    malformed = {"ok": False, "kind": "malformed"}
    if not _plain(e):
        return malformed
    subject, resource, action, context = e.get("subject"), e.get("resource"), e.get("action"), e.get("context")
    if (not _plain(subject) or not _str(subject.get("type")) or not _str(subject.get("id")) or not _plain(resource)
            or not _str(resource.get("type")) or not _str(resource.get("id")) or not _plain(action) or not _str(action.get("name"))
            or not _plain(context) or not _str(context.get("purpose"))):
        return malformed
    # An unknown subject type is unsupported (decision false); a missing counterpart or grant is malformed.
    if subject["type"] not in ("user", "agent"):
        return {"ok": False, "kind": "unsupported"}
    props = subject.get("properties")
    if not _plain(props) or not _str(props.get("grant")) or not _str(props.get("agent") if subject["type"] == "user" else props.get("subject")):
        return malformed
    user = subject["id"] if subject["type"] == "user" else props["subject"]
    agent = props["agent"] if subject["type"] == "user" else subject["id"]
    grant = props["grant"]
    unsupported = {"ok": False, "kind": "unsupported", **({"actor": user} if valid_id(user) else {}), **({"grant": grant} if valid_id(grant) else {})}
    destination = context.get("destination", _MISSING)
    if (not all(valid_id(x) for x in (user, agent, grant, resource["id"])) or resource["type"] != "knowledge"
            or action["name"] not in AUTHZEN_ACTIONS or not context["purpose"] or utf16_length(context["purpose"]) > 128
            or (destination is not _MISSING and not valid_id(destination))):
        return unsupported
    out = {"ok": True, "binding": {"tenant": tenant, "subject": user, "agent": agent, "grant": grant}, "resource": resource["id"],
           "action": action["name"], "purpose": context["purpose"]}
    if destination is not _MISSING:
        out["destination"] = destination
    return out


_MISSING = object()
