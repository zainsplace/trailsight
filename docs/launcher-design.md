# Trailsight Launcher — Design

Status: draft
Date: 2026-09-22

## Summary

A double-clickable launcher that starts the Trailsight dashboard without a
terminal. The user opens the project folder, double-clicks the file for their
operating system, and the dashboard opens in their browser. On first run the
launcher builds an isolated environment and installs Trailsight into it; on
every run after that it goes straight to relaunching under that environment.

## Goal

Trailsight already has a graphical interface: the dashboard shipped in v0.1.
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

`start-trailsight.command` delegates to `start-trailsight.sh` rather than
duplicating its logic. Finder runs `.command` files directly, but the shell
script already does the real work on a POSIX system, so the `.command` file's
whole job is to `cd` into the project root and call the `.sh` file next to it.
That leaves one place to fix if the Unix probing logic ever changes, instead of
two copies drifting apart.

`start-trailsight.bat` looks for `py -3` and `python` on the PATH first, and
only falls back to the Windows registry (`HKCU\Software\Python\PythonCore` and
`HKLM\Software\Python\PythonCore`) when neither works. PATH alone is not
reliable on Windows: the official installer's "Add to PATH" checkbox is
unticked by default, so a machine can have a perfectly good Python 3.12 or
newer installed and registered with the OS while `py` and `python` still
resolve to nothing, or to a different, older interpreter installed by another
tool. The registry keys that the installer always writes are the one place a
launcher can find every installed interpreter regardless of PATH. Each
candidate, from either source, is routed through the same version probe so a
too-old interpreter anywhere in the search is skipped rather than accepted.

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

Phase is decided by comparing `sys.prefix` against the environment directory,
not by comparing interpreter paths. `python -m venv` copies the interpreter
binary on Windows but symlinks it on macOS and Linux, so on those platforms
`sys.executable` resolves to the same real file whether or not the environment
is active; `sys.prefix` does not have that problem, since it points at the
environment's own root regardless of how the interpreter file got there. An
environment variable guards the re-run, so a failed comparison produces a
clear message rather than an endless loop.

A workspace only counts as ready once installation has actually finished. The
launcher writes a marker file, `.venv/.trailsight-ready`, as the last step of
bootstrap, after `install_project` succeeds. `workspace_is_ready` requires both
the interpreter and this marker to exist. If the process is interrupted after
`create_venv` but before the install completes, the interpreter exists but the
marker does not, so the next launch treats the workspace as unfinished and
rebuilds it instead of relaunching into a broken environment.

The isolated environment is what makes this work on every platform. Installing
into a system Python fails outright on current macOS and Debian derivatives,
which refuse the write and report `externally-managed-environment`. A user who
cannot open a terminal cannot recover from that. The environment also leaves the
system Python untouched, and a broken install is repaired by deleting one
folder.

## The module

`src/trailsight/launcher.py`, standard library only.

    venv_python(venv_dir)         Scripts/python.exe on Windows, bin/python elsewhere
    running_inside(venv_dir)      sys.prefix comparison that selects the phase
    find_free_port(preferred)     5000 when bindable, otherwise a free port
    create_venv(venv_dir)         subprocess
    install_project(python, root) subprocess, pip install -e ".[dashboard]"
    workspace_is_ready(venv_dir)  interpreter and readiness marker both present
    mark_workspace_ready(venv_dir) writes the readiness marker
    wait_for_server(port)         polls the socket
    serve(port)                   imports create_app, runs the app
    bootstrap(root, venv_dir)     phase one: create, install, mark ready, relaunch
    relaunch(python, root)        re-runs the launcher under the environment
    run_dashboard()               phase two: picks a port, opens the browser, serves
    _report(message)              prints a message and waits for a keypress
    main()                        orchestration and console output

One constraint governs the module: **nothing from `trailsight` is imported at
module level.** During phase one the package is not installed yet, so a
top-level import of the dashboard would fail before the launcher could install
it. The dashboard import sits inside `serve`, which only runs in phase two.

Re-running uses `subprocess.run` rather than `os.execv`, which is unreliable on
Windows and this is a Windows-first audience.

## What the user sees

First run:

    Trailsight

    Setting up for first use. This takes a minute, and only happens once.
      Creating a private workspace...
      Installing Trailsight...

    Starting Trailsight...
    Opening in your browser: http://127.0.0.1:5000
    If it does not open, type that address into your browser.

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
the reader. `main()` catches it and passes it to `_report`, which prints it and
waits for a keypress before exiting, because a console window that closes on
error leaves the user with a black flash and no information. `_report` is the
one place that prints a message and blocks on `input()`, so both the
`LauncherError` path and the catch-all path below share it instead of
duplicating the print-and-wait block.

Anything that is not a `LauncherError` or a `KeyboardInterrupt` — a port
grabbed between the probe and Flask's bind, an `ImportError` from a damaged
`.venv`, or anything else unanticipated — is caught by a bare `except
Exception` in `main()` and reported through the same `_report` function with a
generic message. No stack trace reaches the user under any of these paths.

| Condition | Message |
|---|---|
| Python older than 3.12 | Trailsight needs Python 3.12 or newer. You have 3.11. Install the latest from python.org, then try again. |
| Install cannot reach the network or disk is full | Could not download or install what Trailsight needs. Check your internet connection and that you have free disk space, then try again. |
| Project folder is not writable | Trailsight could not write to this folder. Move it somewhere like your Documents folder and try again. |
| Relaunch into the environment fails | Trailsight could not start. Delete the .venv folder in this folder and try again. |
| Relaunched process exits non-zero, or an unanticipated exception is caught | Trailsight stopped unexpectedly. Delete the .venv folder in this folder and try again. |
| A second bootstrap is attempted inside the environment | Trailsight could not start in its own workspace. Delete the .venv folder in this folder and try again. |
| No Python found | Reported by the shim, naming python.org. |

## Testing

`tests/test_launcher.py`. No test creates a real environment or runs a real
install; that would make the suite slow and dependent on the network.

- `venv_python` returns the correct path on both platform branches.
- `find_free_port` returns 5000 when it is free, and a different bindable port
  when a socket already holds 5000.
- `running_inside` separates the environment from the system interpreter by
  `sys.prefix`, including the case where a stray interpreter file sits inside
  the venv directory but `sys.prefix` says otherwise.
- `create_venv` and `install_project` are driven with `subprocess.run` replaced,
  asserting the exact command.
- `main()` with its collaborators replaced: a missing environment creates,
  installs, then re-runs; a ready environment goes straight to relaunching.
- Each `LauncherError` path, and an unanticipated exception, produce a plain
  message and no traceback.
- An `ast` walk of the module's top-level body asserts nothing imports from
  `trailsight` at module scope, which is the invariant that makes first-run
  bootstrap possible.

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
  with no terminal use, on a machine that has never run Trailsight.
- The second launch reaches the browser without repeating setup.
- Every failure above prints its message in a window that stays open.
- The command line interface and the core engine are unchanged, and still
  install and run with no extra dependencies.
- `ruff check src tests` is clean and the suite passes.
