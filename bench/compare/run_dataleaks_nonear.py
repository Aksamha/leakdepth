"""dataleaks 0.1.2 without its pairwise near-duplicate detector (see run_dataleaks.py)."""
import os
import runpy

os.environ["DATALEAKS_NO_NEAR"] = "1"
runpy.run_path(os.path.join(os.path.dirname(__file__), "run_dataleaks.py"), run_name="__main__")
