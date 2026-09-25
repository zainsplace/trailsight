# TrailSight Launcher — Design

Status: draft
Date: 2026-09-22

## Summary

A double-clickable launcher that starts the TrailSight dashboard without a
terminal. The user opens the project folder, double-clicks the file for their
operating system, and the dashboard opens in their browser. On first run the
launcher builds an isolated environment and installs TrailSight into it; on
every run after that it goes straight to serving.

## Goal

TrailSight already has a graphical interface: the dashboard shipped in v0.1.
Reaching it does not:

    python -m pip install -e ".[dashboard]"
    trailsight serve

Both steps need a terminal, which is exactly the barrier the dashboard was meant
to remove. This launcher closes that gap. It adds no new interface; it is the
front door to the one that already exists.

The target user has Python installed and has the project folder, but stalls at
the command line.

## How it runs

Three shims sit at the project root, one per platform:

- `start-trailsight.bat` (Windows)
- `start-trailsight.command` (macOS, committed with the executable bit so Finder
  will run it)
- `start-trailsight.sh` (Linux)

Each is a few lines. It locates a Python interpreter, reports a clear message if
there is none, and hands off to `src/trailsight/launcher.py`. Every decision
lives in the launcher module, so the three shims cannot drift apart in
behaviour.

## Two phases

The launcher runs twice, under two different interpreters.

**Phase one — bootstrap.** Runs under whatever Python the shim found. It checks
the version, creates `.venv/` at the project root, installs the project into it
with the dashboard extra, and re-runs itself using the environment's
interpreter.

**Phase two — serve.** Runs under the environment's interpreter, where Flask is
present. It chooses a port, starts a thread that waits for the server socket to
accept connections and then opens the browser, and runs the existing
`create_app()`.

The re-run invokes the environment's interpreter as
`.venv/bin/python -m trailsight.launcher` (`.venv\Scripts\python.exe` on
Windows), with the project root as the working directory.

Phase is decided by comparing `sys.executable` against the environment's
interpreter path. An environment variable guards the re-run, so a failed
comparison produces a clear message rather than an endless loop.

The isolated environment is what makes this work on every platform. Installing
into a system Python fails outright on current macOS and Debian derivatives,
which refuse the write and report `externally-managed-environment`. A user who
cannot open a terminal cannot recover from that. The environment also leaves the
system Python untouched, and a broken install is repaired by deleting one
folder.

## The module

`src/trailsight/launcher.py`, standard library only.

    venv_python(venv_dir)         Scripts/python.exe on Windows, bin/python elsewhere
    running_inside(venv_dir)      path comparison that selects the phase
    find_free_port(preferred)     5000 when bindable, otherwise a free port
    create_venv(venv_dir)         subprocess
    install_project(python, root) subprocess, pip install -e ".[dashboard]"
    wait_for_server(port)         polls the socket
    serve(port)                   imports create_app, runs the app
    main()                        orchestration and console output

One constraint governs the module: **nothing from `trailsight` is imported at
module level.** During phase one the package is not installed yet, so a
top-level import of the dashboard would fail before the launcher could install
it. The dashboard import sits inside `serve`, which only runs in phase two.

Re-running uses `subprocess.run` rather than `os.execv`, which is unreliable on
Windows and this is a Windows-first audience.

## What the user sees

First run:

    TrailSight

    Setting up for first use. This takes a minute, and only happens once.
      Creating a private workspace...
      Installing TrailSight...

    Starting TrailSight...
    Opened in your browser: http://127.0.0.1:5000

    Close this window when you are done.

Later runs omit the setup block and reach the browser in about two seconds.

Port 5000 is preferred but not guaranteed; macOS occupies it with AirPlay
Receiver by default. When it is taken the launcher binds a free port instead and
prints the address it actually used. The user is never asked about ports.

The launcher takes no options. Someone who cannot use a terminal is not running
a local language model, so `--explain` and the Ollama settings stay out of it.
The dashboard's Explain button still works when Ollama happens to be running,
and when it is not, findings are reported in full and only the explanation is
missing. Keeping flags out is what keeps the double-click a double-click.

## Error handling

Failures raise a single `LauncherError` carrying a message already written for
the reader. `main()` catches it, prints it, and waits for a keypress before
exiting, because a console window that closes on error leaves the user with a
black flash and no information. No stack trace reaches the user.

| Condition | Message |
|---|---|
| Python older than 3.12 | TrailSight needs Python 3.12 or newer. You have 3.11. Install the latest from python.org, then try again. |
| Install cannot reach the network | Could not download what TrailSight needs. Check your internet connection and try again. |
| Project folder is not writable | TrailSight could not write to this folder. Move it somewhere like your Documents folder and try again. |
| No Python found | Reported by the shim, naming python.org. |

## Testing

`tests/test_launcher.py`. No test creates a real environment or runs a real
install; that would make the suite slow and dependent on the network.

- `venv_python` returns the correct path on both platform branches.
- `find_free_port` returns 5000 when it is free, and a different bindable port
  when a socket already holds 5000.
- `running_inside` separates the environment's interpreter from the system one.
- `create_venv` and `install_project` are driven with `subprocess.run` replaced,
  asserting the exact command.
- `main()` with its collaborators replaced: a missing environment creates,
  installs, then re-runs; a ready environment goes straight to serving.
- Each `LauncherError` path produces its message and no traceback.

## Packaging

`launcher.py` is part of the package and ships in a wheel with no change to
`pyproject.toml`. The shims live at the project root only, which is correct:
this path assumes someone who has the folder.

`.gitignore` already ignores `.venv/`, so no change is needed there.

The README gains a quick start section describing the double-click, placed above
the command line usage, since it becomes the easier of the two paths.

## Non-goals

- No new interface. The dashboard is unchanged.
- No installer, no packaged binary, no desktop shortcut. Those serve a user with
  no Python at all, which is a separate piece of work.
- No configuration. No ports, no hosts, no model settings.
- No management of the environment beyond creating it. Upgrades are handled by
  deleting `.venv/` and launching again.

## Success criteria

- Double-clicking the file for the platform opens the dashboard in a browser
  with no terminal use, on a machine that has never run TrailSight.
- The second launch reaches the browser without repeating setup.
- Every failure above prints its message in a window that stays open.
- The command line interface and the core engine are unchanged, and still
  install and run with no extra dependencies.
- `ruff check src tests` is clean and the suite passes.
