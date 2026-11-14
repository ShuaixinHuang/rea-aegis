"""Reproduce runtime/export/key separation, with optional real REA analysis."""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import rea_aegis
from rea_aegis.protect import keygen, protect

parser = argparse.ArgumentParser()
parser.add_argument(
    "--rea-entry", type=Path, help="Optional trusted REA scripts/rea.mjs entrypoint"
)
args = parser.parse_args()
node = shutil.which("node")
if node is None:
    parser.error("Node.js is required")
fixture = Path(__file__).resolve().parents[1] / "examples" / "policy"
report = {
    "tool_version": rea_aegis.__version__,
    "node": subprocess.check_output([node, "--version"], text=True).strip(),
    "source_sha256": hashlib.sha256((fixture / "policy.cjs").read_bytes()).hexdigest(),
}
with tempfile.TemporaryDirectory(prefix="rea-aegis-proof-") as directory:
    root = Path(directory)
    original, protected = root / "original", root / "protected"
    shutil.copytree(fixture, original)
    protected.mkdir()
    shutil.copyfile(fixture / "package.json", protected / "package.json")
    key = root / "operator" / "master.key"
    keygen(key)
    protect(original / "policy.cjs", protected / "policy.cjs", key, "commonjs")
    base_env = {k: v for k, v in os.environ.items() if k != "REA_AEGIS_KEY_FILE"}
    protected_env = {**base_env, "REA_AEGIS_KEY_FILE": str(key)}
    plain = subprocess.check_output(
        [node, str(original / "policy.cjs")], env=base_env, timeout=10
    )
    sealed = subprocess.check_output(
        [node, str(protected / "policy.cjs")], env=protected_env, timeout=10
    )
    assert plain == sealed and json.loads(plain) == [32, 111]
    for folder, env in [(original, base_env), (protected, protected_env)]:
        result = subprocess.check_output(
            [
                node,
                "-e",
                "const f=require(process.argv[1]);console.log(JSON.stringify([f(1),f(4)]));",
                str(folder / "policy.cjs"),
            ],
            env=env,
            timeout=10,
        )
        assert json.loads(result) == [32, 111]
    missing = subprocess.run(
        [node, str(protected / "policy.cjs")],
        env=base_env,
        capture_output=True,
        timeout=10,
    )
    assert missing.returncode != 0 and missing.stdout == b""
    report.update(
        runtime_output=[32, 111],
        module_export_matches=True,
        missing_key_rejected=True,
        artifact_bytes={
            "original": (original / "policy.cjs").stat().st_size,
            "protected": (protected / "policy.cjs").stat().st_size,
        },
    )
    if args.rea_entry:
        report["analysis"] = {}
        for label, folder in [("original", original), ("protected", protected)]:
            stdout, stderr = root / f"{label}.json", root / f"{label}.err"
            with stdout.open("w") as out, stderr.open("w") as err:
                result = subprocess.run(
                    [
                        node,
                        str(args.rea_entry.resolve()),
                        "analyze-javascript-application",
                        str(folder),
                        "--format",
                        "json",
                        "--analysis-timeout-ms",
                        "30000",
                    ],
                    stdout=out,
                    stderr=err,
                    timeout=65,
                )
            assert result.returncode == 0, (
                f"REA failed for {label}; inspect the selected analyzer"
            )
            graph = json.loads(stdout.read_text())["normalized_result"]["graph"]
            observed = any(
                observation.get("properties", {}).get("semantic_role")
                == "export-binding"
                and observation["properties"].get("local_name") == "quote"
                for entry in graph["nodes"]
                for observation in entry.get("observations", [])
            )
            report["analysis"][label] = {
                "graph_coverage": graph["coverage"],
                "original_business_export_observed": observed,
            }
        report["analysis"]["operation"] = "analyze_javascript_application"
        report["analysis"]["timeout_ms"] = 30000
        assert report["analysis"]["original"]["original_business_export_observed"]
        assert not report["analysis"]["protected"]["original_business_export_observed"]
        assert all(
            report["analysis"][label]["graph_coverage"]["status"] == "complete"
            for label in ("original", "protected")
        )
        revision = subprocess.run(
            [
                "git",
                "-C",
                str(args.rea_entry.resolve().parent.parent),
                "rev-parse",
                "HEAD",
            ],
            capture_output=True,
            text=True,
        )
        report["analysis"]["analyzer_source_revision"] = (
            revision.stdout.strip() if revision.returncode == 0 else None
        )
        report["analysis"]["entry_sha256"] = hashlib.sha256(
            args.rea_entry.read_bytes()
        ).hexdigest()
print(json.dumps(report, indent=2))
