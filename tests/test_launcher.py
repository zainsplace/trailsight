import os
import sys

from trailsight import launcher


def test_project_root_holds_the_pyproject():
    assert (launcher.project_root() / "pyproject.toml").exists()


def test_venv_dir_sits_beside_the_project(tmp_path):
    assert launcher.venv_dir(tmp_path) == tmp_path / ".venv"


def test_venv_python_matches_the_platform(tmp_path):
    path = launcher.venv_python(tmp_path / ".venv")
    if os.name == "nt":
        assert path.parts[-2:] == ("Scripts", "python.exe")
    else:
        assert path.parts[-2:] == ("bin", "python")


def test_running_inside_is_false_for_the_system_interpreter(tmp_path):
    assert launcher.running_inside(tmp_path / ".venv") is False


def test_running_inside_is_true_for_the_environment_interpreter(tmp_path, monkeypatch):
    venv = tmp_path / ".venv"
    python = launcher.venv_python(venv)
    python.parent.mkdir(parents=True)
    python.touch()
    monkeypatch.setattr(sys, "executable", str(python))
    assert launcher.running_inside(venv) is True
