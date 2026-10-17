#!/usr/bin/env python3
import argparse
import csv
import datetime
import io
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid


class Stopped(Exception):
    pass


def command(argv, timeout=120, capture=True):
    return subprocess.run(argv, check=True, text=True, timeout=timeout,
                          stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                          stderr=subprocess.PIPE)


def stop(signum, frame):
    raise Stopped(f"received signal {signum}")


def listed_jails(include_dying=False):
    argv = ["jls"] + (["-d"] if include_dying else []) + ["-n", "jid", "name"]
    rows = []
    for line in command(argv).stdout.splitlines():
        fields = dict(item.split("=", 1) for item in shlex.split(line) if "=" in item)
        rows.append((int(fields["jid"]), fields["name"]))
    return rows


def cleanup_names(run):
    info = json.loads((run / "run.json").read_text())
    prefix = info["prefix"]
    names = list(dict.fromkeys((run / "names.txt").read_text().splitlines()))
    if not prefix.startswith("jidbench_") or not prefix.replace("_", "").isalnum():
        raise ValueError("invalid cleanup prefix")
    if any(not n.startswith(prefix + "_") or
           not n[len(prefix) + 1:].isdigit() for n in names):
        raise ValueError("invalid cleanup journal")
    return info, names


def cleanup(run, order="reverse", drain_timeout=30):
    """Time only journaled names; never remove a jail using a reusable numeric ID."""
    start = time.perf_counter_ns()
    _, names = cleanup_names(run)
    if order == "reverse":
        names.reverse()
    attempt = (run / "cleanup" /
               (datetime.datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]))
    attempt.mkdir(parents=True)
    failures = []
    summary = {"order": order, "journaled_names": len(names), "removed": 0,
               "already_gone": 0, "not_live": 0, "failures": failures,
               "command_total_ns": 0, "verification_total_ns": 0,
               "directory": str(attempt.relative_to(run)),
               "drain_requested": drain_timeout > 0}
    snapshot_start = time.perf_counter_ns()
    try:
        wanted = set(names)
        live = {name: jid for jid, name in listed_jails() if name in wanted}
    except (subprocess.SubprocessError, ValueError, KeyError) as exc:
        live = None
        summary["initial_snapshot_error"] = str(exc)
    summary["initial_snapshot_ns"] = time.perf_counter_ns() - snapshot_start
    summary["initial_tracked_live"] = len(live) if live is not None else None
    remaining = len(live) if live is not None else None
    removal_start = time.perf_counter_ns()
    with (attempt / "deletion.csv").open("w", buffering=1) as stream, \
         (run / "cleanup.log").open("a", buffering=1) as log:
        writer = csv.writer(stream)
        writer.writerow(["attempt", "tracked_live_before", "name", "initial_jid", "status",
                         "elapsed_ns", "verification_ns"])
        for index, name in enumerate(names, 1):
            before = remaining
            jid = live.get(name, "") if live is not None else ""
            elapsed = verification = 0
            status = "removed"
            if live is not None and name not in live:
                status = "not_live"
                summary["not_live"] += 1
            else:
                command_start = time.perf_counter_ns()
                try:
                    command(["jail", "-r", name], timeout=60)
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
                    elapsed = time.perf_counter_ns() - command_start
                    check_start = time.perf_counter_ns()
                    try:
                        # Confirm disappearance using a successful listing, rather
                        # than treating every jls failure as evidence of absence.
                        present = any(n == name for _, n in listed_jails())
                    except (subprocess.SubprocessError, ValueError, KeyError):
                        present = True
                    verification = time.perf_counter_ns() - check_start
                    if present:
                        status = "failed"
                        failures.append(name)
                        log.write(f"{name}: {exc}; {getattr(exc, 'stderr', '')}\n")
                    else:
                        status = "already_gone"
                        summary["already_gone"] += 1
                else:
                    elapsed = time.perf_counter_ns() - command_start
                    summary["removed"] += 1
                if status != "failed" and remaining is not None:
                    remaining -= 1
            summary["command_total_ns"] += elapsed
            summary["verification_total_ns"] += verification
            writer.writerow([index, before if before is not None else "", name, jid,
                             status, elapsed, verification])
            if index % 1000 == 0 or index == len(names):
                print(f"Cleanup progress: {index}/{len(names)} journaled names processed", flush=True)
    summary["removal_phase_ns"] = time.perf_counter_ns() - removal_start
    drain_start = time.perf_counter_ns()
    deadline = time.monotonic() + drain_timeout
    polls = 0
    remaining_rows = []
    wanted = set(names)
    try:
        while True:
            remaining_rows = [(jid, name) for jid, name in listed_jails(True) if name in wanted]
            polls += 1
            if not remaining_rows or time.monotonic() >= deadline:
                break
            time.sleep(min(0.25, max(0, deadline - time.monotonic())))
        summary["drain_complete"] = not remaining_rows
    except (subprocess.SubprocessError, ValueError, KeyError) as exc:
        summary["drain_complete"] = False
        summary["drain_error"] = str(exc)
    summary["drain_observation_ns"] = time.perf_counter_ns() - drain_start
    summary["drain_polls"] = polls
    summary["remaining_prisons"] = [{"jid": jid, "name": name} for jid, name in remaining_rows]
    summary["total_ns"] = time.perf_counter_ns() - start
    (attempt / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"Cleanup: {summary['removed']} removed, "
          f"{summary['command_total_ns'] / 1e9:.3f}s in removal commands, "
          f"{summary['drain_observation_ns'] / 1e9:.3f}s observing final release; "
          f"results: {attempt}", flush=True)
    return summary


def record_cleanup(info, summary):
    info["cleanup_failures"] = summary["failures"]
    info["cleanup_last"] = summary
    info.setdefault("cleanup_history", []).append(summary["directory"])
    info["cleanup_pending"] = bool(summary["failures"] or not summary["drain_complete"])


def cleanup_failed(summary):
    return bool(summary["failures"] or summary.get("drain_error") or
                (summary["drain_requested"] and not summary["drain_complete"]))


def trace_cleanup(run, args):
    info, names = cleanup_names(run)
    wanted = set(names)
    if not any(name in wanted for _, name in listed_jails(True)):
        raise ValueError("no retained benchmark prisons; create a fresh run with KEEP_JAILS=yes")
    report = args.trace_cleanup.resolve()
    report.parent.mkdir(parents=True, exist_ok=True)
    diagnostics = report.with_name(report.name + ".stderr")
    if report.exists() or diagnostics.exists():
        raise ValueError("trace report/stderr already exists; choose a new TRACE_LABEL")
    source = Path(__file__).resolve().with_name("cleanup.d").read_text()
    anchor = 'inline string bench_prefix = "jidbench_";'
    if source.count(anchor) != 1:
        raise ValueError("unexpected cleanup.d prefix definition")
    source = source.replace(anchor, 'inline string bench_prefix = "' + info["prefix"] + '_";')
    # DTrace -c splits on whitespace. A whitespace-free wrapper path permits
    # arbitrary runner/run paths; the wrapper exec keeps the target PID stable.
    with tempfile.TemporaryDirectory(prefix="jid-cleanup-trace-", dir="/tmp") as directory:
        wrapper = Path(directory) / "cleanup.sh"
        argv = [sys.executable, str(Path(__file__).resolve()), "--cleanup-run", str(run.resolve()),
                "--cleanup-order", args.cleanup_order, "--drain-timeout", str(args.drain_timeout)]
        wrapper.write_text("#!/bin/sh\nexec " + shlex.join(argv) + "\n")
        wrapper.chmod(0o700)
        script = Path(directory) / "cleanup.d"
        script.write_text(source)
        argv = [args.dtrace] + shlex.split(args.dtrace_flags) + [
            "-Z", "-q", "-o", str(report), "-s", str(script), "-c", str(wrapper)]
        with diagnostics.open("w") as stream:
            result = subprocess.run(argv, stdout=subprocess.DEVNULL, stderr=stream)
    print(f"Cleanup trace: {report}; diagnostics: {diagnostics}", flush=True)
    if diagnostics.stat().st_size:
        print("DTrace produced diagnostics; inspect stderr for drops/errors.", file=sys.stderr)
    # DTrace may exit zero despite a failed -c command: inspect the child's
    # persisted result, and ensure it actually performed a fresh cleanup.
    updated = json.loads((run / "run.json").read_text())
    last = updated.get("cleanup_last")
    previous = info.get("cleanup_last", {}).get("directory")
    if not last or last.get("directory") == previous:
        print("No new cleanup result: tracing may have failed before cleanup started.", file=sys.stderr)
        return 1
    return result.returncode or int(cleanup_failed(last))


def positive(value):
    n = int(value)
    if n < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return n


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-jails", type=positive, default=10000)
    parser.add_argument("--list-every", type=positive, default=100,
                        help="sample at 0, 1, every N jails, and the final count")
    parser.add_argument("--repeats", type=positive, default=5)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--modes", default="jid,default",
                        help="comma-separated jls modes: jid,default,all")
    parser.add_argument("--probe", type=Path, help="compiled jail_get_bench executable")
    parser.add_argument("--pause-at", default="",
                        help="comma-separated counts to pause at for external tracing")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--allow-existing", action="store_true")
    parser.add_argument("--keep-jails", action="store_true",
                        help="retain jails after a successful run for a separate cleanup trace")
    parser.add_argument("--cleanup-order", choices=("reverse", "forward"), default="reverse")
    parser.add_argument("--drain-timeout", type=float, default=30,
                        help="seconds to observe final release; 0 makes one observation")
    parser.add_argument("--trace-cleanup", type=Path, help="trace cleanup into this report")
    parser.add_argument("--dtrace", default="dtrace")
    parser.add_argument("--dtrace-flags", default="-x nolibs")
    parser.add_argument("--cleanup-run", type=Path,
                        help="remove names journaled in a previous run directory")
    args = parser.parse_args()
    if platform.system() != "FreeBSD" or os.geteuid() != 0:
        parser.error("run as root on a FreeBSD benchmark host")
    for tool in ("jail", "jls", "sysctl"):
        if shutil.which(tool) is None:
            parser.error(f"missing command: {tool}")
    if command(["sysctl", "-n", "security.jail.jailed"]).stdout.strip() != "0":
        parser.error("run on the host, outside a jail")
    if not (0 <= args.drain_timeout < float("inf")):
        parser.error("--drain-timeout must be finite and nonnegative")
    if args.trace_cleanup and not args.cleanup_run:
        parser.error("--trace-cleanup requires --cleanup-run")
    if args.cleanup_run:
        if args.trace_cleanup:
            return trace_cleanup(args.cleanup_run, args)
        info = json.loads((args.cleanup_run / "run.json").read_text())
        summary = cleanup(args.cleanup_run, args.cleanup_order, args.drain_timeout)
        record_cleanup(info, summary)
        (args.cleanup_run / "run.json").write_text(json.dumps(info, indent=2) + "\n")
        return int(cleanup_failed(summary))
    modes = args.modes.split(",")
    try:
        pauses = {positive(n) for n in args.pause_at.split(",") if n}
    except (ValueError, argparse.ArgumentTypeError):
        parser.error("invalid --pause-at counts")
    if any(n > args.max_jails for n in pauses):
        parser.error("--pause-at counts must not exceed --max-jails")
    if args.warmups < 0 or any(m not in ("jid", "default", "all") for m in modes):
        parser.error("invalid warmups or modes")
    if args.probe:
        args.probe = args.probe.resolve(strict=True)
        if not os.access(args.probe, os.X_OK):
            parser.error("probe must be executable")
    existing_live = command(["jls", "-n", "jid"]).stdout.splitlines()
    existing_all = command(["jls", "-d", "-n", "jid"]).stdout.splitlines()
    if existing_all and not args.allow_existing:
        parser.error("existing or dying jails found; use an empty host or --allow-existing")
    run = args.output or Path("jailbench-" + datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
                              + "-" + uuid.uuid4().hex[:6])
    run.mkdir(parents=True, exist_ok=False)
    prefix = "jidbench_" + uuid.uuid4().hex[:12]
    info = {
        "prefix": prefix, "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "uname": list(platform.uname()), "python": sys.version,
        "arguments": {k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()},
        "existing_live": existing_live, "existing_all": existing_all,
        "creation_parameters": ["persist", "path=/", "host=inherit", "ip4=disable", "ip6=disable"],
        "status": "running",
    }
    for key in ("kern.version", "hw.model", "hw.ncpu", "hw.physmem"):
        info[key] = command(["sysctl", "-n", key]).stdout.strip()
    (run / "run.json").write_text(json.dumps(info, indent=2) + "\n")
    (run / "names.txt").touch()
    print(f"Results: {run.resolve()}; jail prefix: {prefix}", flush=True)
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    result = 0
    try:
        with (run / "creation.csv").open("w", buffering=1) as cf, \
             (run / "queries.csv").open("w", buffering=1) as qf, \
             (run / "names.txt").open("a", buffering=1) as journal:
            creation = csv.writer(cf)
            queries = csv.writer(qf)
            creation.writerow(["created_jails", "visible_live_jails", "name", "jid", "elapsed_ns"])
            queries.writerow(["created_jails", "visible_live_jails", "operation", "repeat", "syscalls", "elapsed_ns"])

            def sample(n):
                total = len(existing_live) + n
                for mode in modes:
                    argv = ["jls"] + {"jid": ["-n", "jid"], "default": [], "all": ["-n", "all"]}[mode]
                    for r in range(-args.warmups, args.repeats):
                        start = time.perf_counter_ns()
                        command(argv, capture=False)
                        elapsed = time.perf_counter_ns() - start
                        if r >= 0:
                            queries.writerow([n, total, "jls_" + mode, r, "", elapsed])
                if args.probe:
                    for mode in ("enum", "jid"):
                        output = command([str(args.probe), mode, str(args.repeats + args.warmups)]).stdout
                        for row in csv.DictReader(io.StringIO(output)):
                            if int(row["visible_jails"]) != total:
                                raise RuntimeError("jail population changed during probe")
                            r = int(row["repeat"]) - args.warmups
                            if r >= 0:
                                queries.writerow([n, total, "syscall_" + mode, r,
                                                  row["syscalls"], row["elapsed_ns"]])
                print(f"Sampled {n} created jails ({total} live visible)", flush=True)

            sample(0)
            for n in range(1, args.max_jails + 1):
                name = f"{prefix}_{n:05d}"
                # Journal BEFORE spawning: cleanup covers interrupted creation.
                journal.write(name + "\n")
                start = time.perf_counter_ns()
                out = command(["jail", "-i", "-c", "name=" + name] + info["creation_parameters"])
                elapsed = time.perf_counter_ns() - start
                jid = int(out.stdout.strip())
                creation.writerow([n, len(existing_live) + n, name, jid, elapsed])
                if n == 1 or n % args.list_every == 0 or n == args.max_jails or n in pauses:
                    sample(n)
                if n in pauses:
                    input(f"Paused at {n} jails. Trace from another terminal; press Enter to continue: ")
            info["status"] = "complete"
    except (Exception, KeyboardInterrupt) as exc:
        result = 1
        info["status"] = "interrupted" if isinstance(exc, (Stopped, KeyboardInterrupt)) else "failed"
        info["error"] = str(exc)
        if isinstance(exc, subprocess.CalledProcessError):
            info["stderr"] = exc.stderr
        print(f"Benchmark stopped: {exc}", file=sys.stderr)
    finally:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        if args.keep_jails and result == 0:
            info["cleanup_pending"] = True
            print(f"Retained jails. Remove with: make cleanup-run RUN={shlex.quote(str(run))}", flush=True)
        else:
            print("Removing benchmark jails; this can take time...", flush=True)
            try:
                summary = cleanup(run, args.cleanup_order, args.drain_timeout)
                record_cleanup(info, summary)
                if cleanup_failed(summary):
                    result = 1
                    print("Cleanup incomplete; see cleanup summary and cleanup.log", file=sys.stderr)
            except Exception as exc:
                result = 1
                info["cleanup_error"] = str(exc)
                info["cleanup_pending"] = True
                print(f"Cleanup error: {exc}", file=sys.stderr)
        info["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        (run / "run.json").write_text(json.dumps(info, indent=2) + "\n")
    return result


if __name__ == "__main__":
    sys.exit(main())
