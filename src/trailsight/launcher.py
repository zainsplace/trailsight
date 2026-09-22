import os
import socket
import sys
from pathlib import Path


class LauncherError(Exception):
    pass


def project_root():
    return Path(__file__).resolve().parents[2]


def venv_dir(root):
    return Path(root) / ".venv"


def venv_python(venv):
    venv = Path(venv)
    if os.name == "nt":
        return venv / "Scripts" / "python.exe"
    return venv / "bin" / "python"


def running_inside(venv):
    try:
        return Path(sys.executable).resolve() == venv_python(venv).resolve()
    except OSError:
        return False


PREFERRED_PORT = 5000


def find_free_port(preferred=PREFERRED_PORT):
    for candidate in (preferred, 0):
        with socket.socket() as probe:
            try:
                probe.bind(("127.0.0.1", candidate))
            except OSError:
                continue
            return probe.getsockname()[1]
    raise LauncherError("TrailSight could not find a free port to run on.")
