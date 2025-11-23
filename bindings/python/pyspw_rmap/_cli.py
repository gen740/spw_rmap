from __future__ import annotations

import os
import subprocess
import sys
from importlib import resources


def _run_binary(binary_name: str) -> int:
    """Execute the packaged CLI binary and return its exit code."""
    target = resources.files("pyspw_rmap") / "bin" / binary_name
    if os.name == "nt":
        target = target.with_name(f"{target.name}.exe")

    try:
        with resources.as_file(target) as exe_path:
            completed = subprocess.run(
                [os.fspath(exe_path), *sys.argv[1:]], check=False
            )
    except FileNotFoundError as exc:
        raise SystemExit(
            f"Executable '{binary_name}' is not available in the pyspw_rmap wheel."
        ) from exc
    except OSError as exc:  # Includes PermissionError, etc.
        raise SystemExit(f"Failed to run '{binary_name}': {exc}") from exc

    return completed.returncode


def spwrmap() -> None:
    raise SystemExit(_run_binary("spwrmap"))


def spwrmap_speedtest() -> None:
    raise SystemExit(_run_binary("spwrmap_speedtest"))
