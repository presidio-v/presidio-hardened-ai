import re
from pathlib import Path

import presidio_ai


def test_version_matches_pyproject():
    # __version__ is stamped into evidence records (source_version) and printed by
    # `pai version`; a hand-kept constant drifted from 0.10.0 to a 0.30.0 package.
    pyproject = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text()
    declared = re.search(r'^version = "([^"]+)"', pyproject, re.M).group(1)
    assert presidio_ai.__version__ == declared
