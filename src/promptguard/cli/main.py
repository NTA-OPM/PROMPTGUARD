"""PromptGuard command line interface.

Exit codes (scan): 0 allow / monitor / sanitize · 10 review · 20 block ·
3 input error (unreadable, too large, not text) · 4 policy/config error.
``--fail-on`` controls the threshold: ``review`` (default) fails on review or block,
``block`` only on block, ``never`` always exits 0 (errors still non-zero).
"""

from __future__ import annotations

import json
import sys
from enum import Enum
from pathlib import Path
from typing import Annotated, Any

import typer

from promptguard._version import __version__
from promptguard.core.engine import InputRejected, Scanner, ScannerConfig
from promptguard.core.schema import Action, InputEnvelope, ScanResult, SourceType
from promptguard.policy.engine import PolicyError, load_policy

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="PromptGuard - prompt-injection risk signals and policy recommendations. "
    "Detection is one layer of defense; it does not guarantee prevention.",
)
policy_app = typer.Typer(no_args_is_help=True, help="Validate and inspect policies.")
app.add_typer(policy_app, name="policy")

EXIT_OK, EXIT_REVIEW, EXIT_BLOCK, EXIT_INPUT, EXIT_CONFIG = 0, 10, 20, 3, 4
DEFAULT_MAX_BYTES = 5_000_000


class OutFmt(str, Enum):
    json = "json"
    jsonl = "jsonl"
    text = "text"


class FailOn(str, Enum):
    review = "review"
    block = "block"
    never = "never"


class InFmt(str, Enum):
    text = "text"
    jsonl = "jsonl"


def _err(msg: str) -> None:
    typer.echo(f"error: {msg}", err=True)


def _build_scanner(policy_path: Path | None, max_chars: int | None) -> Scanner:
    try:
        policy = load_policy(policy_path)
    except (PolicyError, OSError) as exc:
        _err(str(exc))
        raise typer.Exit(EXIT_CONFIG) from exc
    cfg = ScannerConfig(max_chars=max_chars) if max_chars else ScannerConfig()
    return Scanner(policy, config=cfg)


def _read_bounded(path: Path, max_bytes: int) -> str:
    if not path.is_file():
        raise InputRejected(f"not a regular file: {path}")
    size = path.stat().st_size
    if size > max_bytes:
        raise InputRejected(f"{path}: {size} bytes exceeds --max-bytes {max_bytes}")
    raw = path.read_bytes()
    if b"\x00" in raw[:8192]:
        raise InputRejected(f"{path}: looks like a binary file; only text is supported")
    return raw.decode("utf-8", errors="replace")


def _envelopes(
    files: list[Path],
    stdin: bool,
    in_fmt: InFmt,
    context: SourceType,
    profile: str | None,
    content_type: str,
    max_bytes: int,
) -> list[tuple[str, InputEnvelope]]:
    items: list[tuple[str, str]] = []
    if stdin:
        data = sys.stdin.buffer.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise InputRejected(f"stdin exceeds --max-bytes {max_bytes}")
        items.append(("<stdin>", data.decode("utf-8", errors="replace")))
    for f in files:
        items.append((str(f), _read_bounded(f, max_bytes)))
    out: list[tuple[str, InputEnvelope]] = []
    for label, text in items:
        if in_fmt is InFmt.text:
            out.append(
                (
                    label,
                    InputEnvelope(
                        text=text,
                        source_type=context,
                        context_profile=profile,
                        content_type=content_type,
                        source_id=label[:256],
                    ),
                )
            )
            continue
        for n, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
                kw: dict[str, Any] = {
                    "text": rec["text"],
                    "source_type": rec.get("source_type", context.value),
                    "context_profile": rec.get("context_profile", profile),
                    "content_type": content_type,
                }
                if "id" in rec:
                    kw["input_id"] = str(rec["id"])
                out.append((f"{label}:{n}", InputEnvelope(**kw)))
            except (ValueError, KeyError, TypeError) as exc:
                raise InputRejected(
                    f"{label}:{n}: invalid JSONL record ({type(exc).__name__})"
                ) from exc
    return out


def _brief(label: str, r: ScanResult) -> str:
    lines = [
        f"{label}: {r.decision.action.value.upper()}  (risk={r.risk.level.value}, profile={r.decision.profile}, {r.duration_ms:.1f} ms)"
    ]
    for f in r.findings[:12]:
        ev = f.evidence[0] if f.evidence else None
        where = f" @{ev.span.start}-{ev.span.end} {ev.snippet!r}" if ev else ""
        lines.append(
            f"  - [{f.severity.value}] {f.category.value} ({f.rule_id or f.detector_id}){where}"
        )
    if len(r.findings) > 12:
        lines.append(f"  … {len(r.findings) - 12} more finding(s)")
    if r.decision.indeterminate:
        lines.append("  ! detector error: result is indeterminate; failure mode applied")
    lines.append(
        "  note: recommendation only; detection is not proof and absence of findings is not proof of safety"
    )
    return "\n".join(lines)


@app.command()
def scan(
    files: Annotated[list[Path] | None, typer.Argument(help="Files to scan (text).")] = None,
    stdin: Annotated[bool, typer.Option("--stdin", help="Read input from standard input.")] = False,
    file: Annotated[
        list[Path] | None, typer.Option("--file", "-f", help="File to scan (repeatable).")
    ] = None,
    context: Annotated[
        SourceType, typer.Option("--context", "-c", help="Where the content came from.")
    ] = SourceType.USER_INPUT,
    profile: Annotated[str | None, typer.Option(help="Force a policy profile.")] = None,
    policy: Annotated[Path | None, typer.Option(help="Policy YAML (default: built-in).")] = None,
    fmt: Annotated[OutFmt, typer.Option("--format", help="Output format.")] = OutFmt.json,
    input_format: Annotated[
        InFmt, typer.Option(help="text, or jsonl with {'text', optional 'source_type','id'}.")
    ] = InFmt.text,
    html: Annotated[
        bool, typer.Option("--html", help="Treat input as HTML (hidden content analysis).")
    ] = False,
    fail_on: Annotated[
        FailOn, typer.Option(help="Exit non-zero at this decision level.")
    ] = FailOn.review,
    max_bytes: Annotated[
        int, typer.Option(help="Maximum input size in bytes.")
    ] = DEFAULT_MAX_BYTES,
    max_chars: Annotated[
        int | None, typer.Option(help="Scan limit in characters (rest is reported as truncated).")
    ] = None,
) -> None:
    """Scan text, files or stdin and print findings plus a policy recommendation."""
    paths = [*(files or []), *(file or [])]
    if not paths and not stdin:
        _err("provide a file argument, --file, or --stdin")
        raise typer.Exit(2)
    scanner = _build_scanner(policy, max_chars)
    try:
        envs = _envelopes(
            paths,
            stdin,
            input_format,
            context,
            profile,
            "text/html" if html else "text/plain",
            max_bytes,
        )
        results = [(lbl, scanner.scan(env)) for lbl, env in envs]
    except (InputRejected, OSError, PolicyError) as exc:
        _err(str(exc))
        raise typer.Exit(EXIT_INPUT if not isinstance(exc, PolicyError) else EXIT_CONFIG) from exc
    if fmt is OutFmt.json:
        payload: Any = [{"source": lbl, **r.model_dump(mode="json")} for lbl, r in results]
        typer.echo(json.dumps(payload[0] if len(payload) == 1 else payload, indent=2))
    elif fmt is OutFmt.jsonl:
        for lbl, r in results:
            typer.echo(json.dumps({"source": lbl, **r.model_dump(mode="json")}))
    else:
        for lbl, r in results:
            typer.echo(_brief(lbl, r))
    worst = max((r.decision.action for _, r in results), default=Action.ALLOW)
    code = (
        EXIT_BLOCK if worst is Action.BLOCK else EXIT_REVIEW if worst is Action.REVIEW else EXIT_OK
    )
    if fail_on is FailOn.never or (fail_on is FailOn.block and code != EXIT_BLOCK):
        code = EXIT_OK
    raise typer.Exit(code)


@app.command()
def evaluate(
    dataset: Annotated[
        Path, typer.Option("--dataset", "-d", help="Dataset directory containing manifest.json.")
    ],
    split: Annotated[str, typer.Option(help="dev, test or all.")] = "dev",
    positive_at: Annotated[
        str, typer.Option(help="Count review+block (review) or only block as 'detected'.")
    ] = "review",
    context_mode: Annotated[
        str,
        typer.Option(help="labeled: use per-example source_type; ignore: treat all as user input."),
    ] = "labeled",
    policy: Annotated[Path | None, typer.Option()] = None,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write run JSON here.")
    ] = None,
    min_recall: Annotated[
        float | None, typer.Option(help="CI gate: fail if recall is below this.")
    ] = None,
    max_fpr: Annotated[
        float | None, typer.Option(help="CI gate: fail if false-positive rate exceeds this.")
    ] = None,
) -> None:
    """Run the reproducible benchmark. Exit 1 if a --min-recall/--max-fpr gate fails."""
    from promptguard.evaluation.dataset import DatasetError, load_dataset
    from promptguard.evaluation.report import to_markdown
    from promptguard.evaluation.runner import evaluate as run_eval

    if positive_at not in ("review", "block") or context_mode not in ("labeled", "ignore"):
        _err("--positive-at must be review|block and --context-mode labeled|ignore")
        raise typer.Exit(2)
    scanner = _build_scanner(policy, None)
    try:
        ds = load_dataset(dataset)
        run = run_eval(ds, scanner, split=split, positive_at=positive_at, context_mode=context_mode)  # type: ignore[arg-type]
    except (DatasetError, ValueError) as exc:
        _err(str(exc))
        raise typer.Exit(EXIT_INPUT) from exc
    if output:
        output.write_text(json.dumps(run, indent=2), encoding="utf-8")
    typer.echo(to_markdown(run))
    o = run["metrics"]["overall"]
    failed = []
    if min_recall is not None and (o["recall"] is None or o["recall"] < min_recall):
        failed.append(f"recall {o['recall']} < {min_recall}")
    if max_fpr is not None and (o["fpr"] is not None and o["fpr"] > max_fpr):
        failed.append(f"FPR {o['fpr']} > {max_fpr}")
    if failed:
        _err("regression gate failed: " + "; ".join(failed))
        raise typer.Exit(1)


@app.command()
def report(
    run_file: Annotated[Path, typer.Argument(help="Run JSON written by `evaluate --output`.")],
    fmt: Annotated[str, typer.Option("--format", help="html or md")] = "html",
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
) -> None:
    """Render an evaluation run as an HTML report or Markdown benchmark card."""
    from promptguard.evaluation.report import to_html, to_markdown

    try:
        run = json.loads(run_file.read_text(encoding="utf-8"))
        text = to_html(run) if fmt == "html" else to_markdown(run)
    except (OSError, ValueError, KeyError) as exc:
        _err(f"cannot render report: {type(exc).__name__}: {exc}")
        raise typer.Exit(EXIT_INPUT) from exc
    if output:
        output.write_text(text, encoding="utf-8")
        typer.echo(f"wrote {output}")
    else:
        typer.echo(text)


@policy_app.command("validate")
def policy_validate(path: Annotated[Path, typer.Argument()]) -> None:
    """Validate a policy file (schema, monotonic thresholds, required profiles, checksum)."""
    try:
        p = load_policy(path)
    except (PolicyError, OSError) as exc:
        _err(str(exc))
        raise typer.Exit(EXIT_CONFIG) from exc
    typer.echo(
        f"OK  {p.policy_id}@{p.version}  hash={p.canonical_hash()}  profiles={len(p.profiles)}"
    )


@policy_app.command("hash")
def policy_hash(path: Annotated[Path, typer.Argument()]) -> None:
    """Print the canonical hash to store in the policy's `checksum:` field."""
    try:
        typer.echo(load_policy(path).canonical_hash())
    except (PolicyError, OSError) as exc:
        _err(str(exc))
        raise typer.Exit(EXIT_CONFIG) from exc


@app.command()
def detectors() -> None:
    """List registered detectors and versions."""
    for m in Scanner().manifests():
        typer.echo(f"{m.id:12} v{m.version:8} required={m.required!s:5} {m.description}")


@app.command()
def version() -> None:
    """Print version."""
    typer.echo(__version__)


if __name__ == "__main__":  # pragma: no cover
    app()
