import os
import socket
import subprocess
import sys

import pytest

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


def _port_is_free(port):
    with socket.socket() as probe:
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def test_find_free_port_prefers_the_default():
    if not _port_is_free(launcher.PREFERRED_PORT):
        pytest.skip("the preferred port is already in use on this machine")
    assert launcher.find_free_port() == launcher.PREFERRED_PORT


def test_find_free_port_falls_back_when_the_default_is_taken():
    with socket.socket() as taken:
        taken.bind(("127.0.0.1", 0))
        busy = taken.getsockname()[1]
        chosen = launcher.find_free_port(busy)
    assert chosen != busy
    assert chosen > 0


class RecordingRun:
    def __init__(self, returncode=0):
        self.calls = []
        self.returncode = returncode

    def __call__(self, command, **kwargs):
        self.calls.append((command, kwargs))
        if self.returncode != 0:
            raise subprocess.CalledProcessError(self.returncode, command)
        return subprocess.CompletedProcess(command, 0)


def test_check_python_version_rejects_old_interpreters(monkeypatch):
    monkeypatch.setattr(launcher.sys, "version_info", (3, 11, 0))
    with pytest.raises(launcher.LauncherError) as error:
        launcher.check_python_version()
    assert "3.11" in str(error.value)
    assert "python.org" in str(error.value)


def test_check_python_version_accepts_the_current_interpreter():
    assert launcher.check_python_version() is None


def test_create_venv_runs_the_venv_module(monkeypatch, tmp_path):
    run = RecordingRun()
    monkeypatch.setattr(launcher.subprocess, "run", run)
    launcher.create_venv(tmp_path / ".venv")
    command, _ = run.calls[0]
    assert command[:3] == [sys.executable, "-m", "venv"]
    assert command[3] == str(tmp_path / ".venv")


def test_create_venv_failure_suggests_another_folder(monkeypatch, tmp_path):
    monkeypatch.setattr(launcher.subprocess, "run", RecordingRun(returncode=1))
    with pytest.raises(launcher.LauncherError) as error:
        launcher.create_venv(tmp_path / ".venv")
    assert "Documents" in str(error.value)


def test_install_project_installs_the_dashboard_extra(monkeypatch, tmp_path):
    run = RecordingRun()
    monkeypatch.setattr(launcher.subprocess, "run", run)
    launcher.install_project(tmp_path / "python", tmp_path)
    command, kwargs = run.calls[0]
    assert command[0] == str(tmp_path / "python")
    assert command[1:] == ["-m", "pip", "install", "-e", ".[dashboard]"]
    assert kwargs["cwd"] == str(tmp_path)


def test_install_failure_mentions_the_connection(monkeypatch, tmp_path):
    monkeypatch.setattr(launcher.subprocess, "run", RecordingRun(returncode=1))
    with pytest.raises(launcher.LauncherError) as error:
        launcher.install_project(tmp_path / "python", tmp_path)
    assert "internet connection" in str(error.value)


def test_wait_for_server_returns_true_once_the_socket_accepts():
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        assert launcher.wait_for_server(port, timeout=5.0) is True


def test_wait_for_server_gives_up_when_nothing_listens():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    assert launcher.wait_for_server(port, timeout=0.3) is False


def test_browser_opens_once_the_server_accepts(monkeypatch):
    opened = []
    monkeypatch.setattr(launcher.webbrowser, "open", opened.append)
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        thread = launcher.open_browser_when_ready(port)
        thread.join(timeout=10)
    assert not thread.is_alive()
    assert opened == [f"http://127.0.0.1:{port}"]


def test_serve_runs_the_dashboard_on_localhost(monkeypatch):
    pytest.importorskip("flask")
    import trailsight.dashboard

    calls = {}

    class StubApp:
        def run(self, host, port):
            calls["host"] = host
            calls["port"] = port

    monkeypatch.setattr(trailsight.dashboard, "create_app", lambda: StubApp())
    launcher.serve(4321)
    assert calls == {"host": "127.0.0.1", "port": 4321}
