import os
import shutil
import sys
import tempfile
from pathlib import Path

# Point the app at a throw-away folder BEFORE it is imported
TMP = Path(tempfile.mkdtemp(prefix="hyshield-test-"))
os.environ["HYSHIELD_DATA"] = str(TMP)
os.environ["HYSHIELD_GEO"] = "off"
os.environ["POLL_SECONDS"] = "3600"   # tests call poll() themselves
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

SAMPLE = Path(__file__).resolve().parent.parent / "data" / "cowrie.json"
shutil.copy(SAMPLE, TMP / "cowrie.json")
