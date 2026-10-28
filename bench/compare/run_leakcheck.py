"""leakcheck (git b9cbae5) via its CLI; detected = exit code 1 (medium) or 2 (high)."""
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _loop import serve


def handle(job):
    test = job["test"] if job["mode"] == "split" else job["other"]
    rep = os.path.join(job["workdir"], "leakcheck.json")
    cmd = [sys.executable, "-m", "leakcheck", "scan", "--train", job["train"], "--test", test,
           "--label", job["label"], "--json", rep]
    if job.get("group"):
        cmd += ["--group", job["group"]]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=1800, cwd=job["workdir"])
    if p.returncode not in (0, 1, 2):
        return {"applicable": True, "detected": None, "detected_any": None,
                "error": f"exit {p.returncode}: {(p.stderr or p.stdout)[-300:]}"}
    detail = {}
    if os.path.exists(rep):
        with open(rep) as f:
            d = json.load(f)
        fs = d.get("findings", d.get("checks", []))
        if isinstance(fs, list):
            detail["findings"] = [{k: x.get(k) for k in ("check", "code", "severity", "level") if k in x}
                                  for x in fs if isinstance(x, dict)][:20]
        os.remove(rep)
    return {"applicable": True, "detected": p.returncode in (1, 2), "detected_any": None,
            "exit_code": p.returncode, "detail": detail, "error": None}


if __name__ == "__main__":
    serve(handle)
