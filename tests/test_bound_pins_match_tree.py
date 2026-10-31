"""The x-bound-images pins in docker-compose.yml always name images built for THIS tree's image inputs.

inputs_digest skips docker-compose.yml, so the check is not circular: pins are written in a compose-only commit
after the founder's prepare, and any later change to an image input makes this test fail until they are renewed.
A tree without pins passes (nothing is claimed). Needs the git checkout (CI); the gateway's exported tree has none.
"""
import re
import subprocess
from pathlib import Path

import pytest

from app import release_gateway as rg

ROOT = Path(__file__).resolve().parents[1]


def _pins():
    lines = [l for l in (ROOT / "docker-compose.yml").read_text().splitlines() if re.match(r"^x-bound-images\s*:", l)]
    assert len(lines) <= 1, "two pin blocks are never authority"
    if not lines:
        return None
    body = lines[0].split(":", 1)[1].strip().strip("{}")
    return {k.strip(): v.strip().strip("'\"") for k, v in (part.split(":", 1) for part in body.split(","))}


def test_the_pins_name_this_trees_image_inputs():
    pins = _pins()
    if pins is None:
        return
    assert set(pins) == {"inputs_sha256", "api", "worker", "reasoner", "egress"}
    if subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True).returncode != 0:
        pytest.skip("not a git checkout (the gateway checks an exported tree)")
    dirty = subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain", "--", *rg.DEPLOY_PATHS],
                           capture_output=True, text=True).stdout.strip()
    if dirty:
        pytest.skip("uncommitted changes to image inputs: HEAD is not this tree")
    assert pins["inputs_sha256"] == rg.inputs_digest(rg.release_archive(ROOT, "HEAD"))
