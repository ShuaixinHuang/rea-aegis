"""Exercise an installed wheel from outside its source checkout."""

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import rea_aegis
from rea_aegis.protect import keygen, protect

package_root = Path(os.environ["PYTHONPATH"]).resolve()
assert Path(rea_aegis.__file__).resolve().is_relative_to(package_root)
with tempfile.TemporaryDirectory(prefix="rea-aegis-installed-") as directory:
    root = Path(directory)
    key = root / "operator" / "master.key"
    source = root / "input.cjs"
    source.write_text("module.exports = 42; console.log(JSON.stringify({total:13.5}));")
    release = root / "release"
    release.mkdir()
    keygen(key)
    protect(source, release / "entry.cjs", key, "commonjs")
    result = subprocess.run(
        [shutil.which("node"), str(release / "entry.cjs")],
        env={**os.environ, "REA_AEGIS_KEY_FILE": str(key)},
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )
    assert json.loads(result.stdout) == {"total": 13.5}
print("Installed wheel: authenticated CommonJS runtime passed")
