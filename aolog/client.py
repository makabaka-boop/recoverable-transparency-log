"""Command line client and independent auditor.

The ``audit`` command never asks the service whether proofs are valid.  It
downloads records and hashes, canonicalizes records, derives proof ranges
locally, reconstructs roots, and checks the previous locally stored tree head.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from .canonical import canonicalize, canonicalize_input
from .server import build_server
from .verifier import ProofError, verify_consistency, verify_inclusion


def _request(base: str, method: str, path: str, body: bytes | None = None) -> tuple[int, bytes]:
    request = urllib.request.Request(
        base.rstrip("/") + path,
        data=body,
        method=method,
        headers={"Content-Type": "application/json"} if body is not None else {},
    )
    try:
        with urllib.request.urlopen(request) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _json(base: str, method: str, path: str, value: Any | None = None) -> Any:
    body = canonicalize(value) if value is not None else None
    status, raw = _request(base, method, path, body)
    parsed = json.loads(raw.decode("utf-8"))
    if status >= 400:
        raise RuntimeError(parsed.get("error", raw.decode("utf-8", "replace")))
    return parsed


def cmd_serve(args: argparse.Namespace) -> int:
    server = build_server(args.directory, args.host, args.port,
                          crash_at=args.crash_at, verbose=args.verbose)
    host, port = server.server_address
    print(json.dumps({"listening": f"http://{host}:{port}"}), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.store.close()
    return 0


def cmd_append(args: argparse.Namespace) -> int:
    records = [json.loads(canonicalize_input(item)) for item in args.records]
    result = _json(args.base, "POST", "/v1/append", {"records": records})
    print(canonicalize(result).decode())
    return 0


def cmd_head(args: argparse.Namespace) -> int:
    result = _json(args.base, "GET", "/v1/head")
    print(canonicalize(result).decode())
    return 0


def cmd_record(args: argparse.Namespace) -> int:
    status, raw = _request(args.base, "GET", f"/v1/records/{args.index}")
    if status >= 400:
        raise RuntimeError(raw.decode("utf-8", "replace"))
    # Parse only to reject a malformed record response.  The auditor
    # canonicalizes this parsed value itself; it does not trust service bytes.
    json.loads(raw.decode("utf-8"))
    sys.stdout.buffer.write(raw + b"\n")
    return 0


def cmd_proof(args: argparse.Namespace) -> int:
    result = _json(args.base, "GET", f"/v1/proof?index={args.index}&size={args.size}")
    print(canonicalize(result).decode())
    return 0


def cmd_consistency(args: argparse.Namespace) -> int:
    path = f"/v1/consistency?old_size={args.old_size}&new_size={args.new_size}"
    result = _json(args.base, "GET", path)
    print(canonicalize(result).decode())
    return 0


def _write_audit_state(path: Path, head: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(canonicalize(head))
    temporary.replace(path)


def cmd_audit(args: argparse.Namespace) -> int:
    state_path = Path(args.state)
    if state_path.exists():
        old_state = json.loads(state_path.read_bytes().decode("utf-8"))
        old_size = int(old_state["tree_size"])
        old_root = bytes.fromhex(old_state["root_hash"])
    else:
        old_size = 0
        from .tree import EMPTY_HASH
        old_root = EMPTY_HASH

    head = _json(args.base, "GET", "/v1/head")
    new_size = int(head["tree_size"])
    new_root = bytes.fromhex(head["root_hash"])

    if new_size < old_size:
        raise RuntimeError("server tree shrank since the previous audit")

    # Independently verify prefix consistency before trusting new records.
    consistency = _json(
        args.base,
        "GET",
        f"/v1/consistency?old_size={old_size}&new_size={new_size}",
    )
    verify_consistency(
        old_size=old_size,
        new_size=new_size,
        old_root=old_root,
        new_root=new_root,
        proof=[bytes.fromhex(x) for x in consistency["hashes"]],
    )

    # Fetch and canonicalize every record, then verify an inclusion proof for
    # each leaf. No service-provided "verified" field is consumed.
    for index in range(old_size, new_size):
        status, raw = _request(args.base, "GET", f"/v1/records/{index}")
        if status >= 400:
            raise RuntimeError(f"could not download record {index}")
        record_value = json.loads(raw.decode("utf-8"))
        # Re-normalize locally; raw bytes are untrusted.
        normalized = canonicalize(record_value)
        proof = _json(args.base, "GET", f"/v1/proof?index={index}&size={new_size}")
        verify_inclusion(
            record_value=json.loads(normalized),
            index=index,
            size=new_size,
            root=new_root,
            proof=[bytes.fromhex(x) for x in proof["hashes"]],
        )

    _write_audit_state(state_path, head)
    print(canonicalize({
        "status": "verified",
        "tree_size": new_size,
        "root_hash": new_root.hex(),
    }).decode())
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aolog", description="Append-only audit log")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="run the HTTP service")
    serve.add_argument("--directory", required=True)
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument("--crash-at", choices=["after_records"],
                       help="test hook: exit after fsyncing records, before head publish")
    serve.add_argument("--verbose", action="store_true")
    serve.set_defaults(func=cmd_serve)

    def add_base(command: argparse.ArgumentParser) -> None:
        command.add_argument("--base", default="http://127.0.0.1:8080")

    append = sub.add_parser("append", help="append one or more JSON records")
    add_base(append)
    append.add_argument("records", nargs="+", help="JSON document per record")
    append.set_defaults(func=cmd_append)

    head = sub.add_parser("head", help="fetch the published tree head")
    add_base(head)
    head.set_defaults(func=cmd_head)

    record = sub.add_parser("record", help="fetch one record by zero-based sequence number")
    add_base(record)
    record.add_argument("index", type=int)
    record.set_defaults(func=cmd_record)

    proof = sub.add_parser("proof", help="fetch an inclusion proof")
    add_base(proof)
    proof.add_argument("index", type=int)
    proof.add_argument("--size", type=int)
    proof.set_defaults(func=cmd_proof)

    consistency = sub.add_parser("consistency", help="fetch a consistency proof")
    add_base(consistency)
    consistency.add_argument("old_size", type=int)
    consistency.add_argument("new_size", type=int)
    consistency.set_defaults(func=cmd_consistency)

    audit = sub.add_parser("audit", help="independently verify and advance audit state")
    add_base(audit)
    audit.add_argument("--state", default="audit-state.json")
    audit.set_defaults(func=cmd_audit)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "proof" and args.size is None:
        head = _json(args.base, "GET", "/v1/head")
        args.size = int(head["tree_size"])
    try:
        return int(args.func(args) or 0)
    except (RuntimeError, ProofError, UnicodeError, ValueError, KeyError) as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
