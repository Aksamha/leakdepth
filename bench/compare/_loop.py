"""JSON-lines worker loop shared by the tool runners (one job per stdin line)."""
import contextlib
import json
import sys
import time
import traceback
import warnings

MARK = "@@leakbench "


def serve(handle):
    warnings.filterwarnings("ignore")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        job = json.loads(line)
        t0 = time.time()
        try:
            with contextlib.redirect_stdout(sys.stderr):  # tools print reports; keep the channel clean
                out = handle(job)
        except Exception as e:  # noqa: BLE001
            out = {"applicable": True, "detected": None, "detected_any": None,
                   "error": f"{type(e).__name__}: {e}"[:300], "trace": traceback.format_exc()[-600:]}
        out["seconds"] = round(time.time() - t0, 2)
        sys.__stdout__.write(MARK + json.dumps(out, default=str) + "\n")
        sys.__stdout__.flush()
