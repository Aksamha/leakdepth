"""splitcheck 0.2.0 via its CLI; detected = non-zero exit with leakage above --max-leakage (default 0)."""
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _loop import serve

EXE = os.path.join(os.path.dirname(sys.executable), "splitcheck")


def handle(job):
    test = job["test"] if job["mode"] == "split" else job["other"]
    cmd = [EXE, "check", job["train"], test, "--json"]
    if job.get("group"):
        cmd += ["--on", job["group"]]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    if p.returncode not in (0, 1):
        return {"applicable": True, "detected": None, "detected_any": None,
                "error": f"exit {p.returncode}: {(p.stderr or p.stdout)[-300:]}"}
    return {"applicable": True, "detected": p.returncode == 1, "detected_any": p.returncode == 1,
            "exit_code": p.returncode, "detail": {"stdout": p.stdout[-400:]}, "error": None}


if __name__ == "__main__":
    serve(handle)
