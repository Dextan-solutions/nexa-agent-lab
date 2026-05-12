import sys
from pathlib import Path


# Allow local absolute imports (agents.*, db.*, llm.*, etc.) when running pytest.
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

