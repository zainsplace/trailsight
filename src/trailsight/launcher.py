import os
import socket
import subprocess
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


MINIMUM_PYTHON = (3, 12)


def check_python_version():
    if tuple(sys.version_info[:2]) < MINIMUM_PYTHON:
        needed = f"{MINIMUM_PYTHON[0]}.{MINIMUM_PYTHON[1]}"
        current = f"{sys.version_info[0]}.{sys.version_info[1]}"
        raise LauncherError(
            f"TrailSight needs Python {needed} or newer. You have {current}. "
            "Install the latest from python.org, then try again.")


def create_venv(venv):
    try:
        subprocess.run([sys.executable, "-m", "venv", str(venv)],
                       check=True, capture_output=True)
    except (subprocess.CalledProcessError, OSError) as error:
        raise LauncherError(
            "TrailSight could not write to this folder. Move it somewhere "
            "like your Documents folder and try again.") from error


def install_project(python, root):
    try:
        subprocess.run([str(python), "-m", "pip", "install", "-e",
                        ".[dashboard]"],
                       cwd=str(root), check=True, capture_output=True)
    except (subprocess.CalledProcessError, OSError) as error:
        raise LauncherError(
            "Could not download what TrailSight needs. Check your internet "
            "connection and try again.") from error
