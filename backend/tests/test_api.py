# Lightweight static smoke checks for the interview package.
# Runtime API testing is demonstrated by the commands in TESTING.md.
from pathlib import Path

def test_required_files_exist():
    root=Path(__file__).parents[2]
    assert (root/"app"/"main.py").exists()
    assert (root/"requirements.txt").exists()
