#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
import argparse
import csv
import io
import json
import math
import re
import statistics
import sys
import tarfile
import zipfile
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath


def stats(values):
    values = sorted(values)
    n = len(values)
    return (n, statistics.mean(values), statistics.median(values),
            values[math.ceil(.95 * n) - 1], values[math.ceil(.99 * n) - 1],
            values[0], values[-1])


def timing(label, values):
    if not values:
        print(f"  {label}: no samples")
        return
    n, mean, median, p95, p99, low, high = stats(values)
    print(f"  {label}: {n:,} samples; total {sum(values) / 1e9:.3f} s")
    print(f"    ms: mean {mean / 1e6:.3f}, median {median / 1e6:.3f}, "
          f"p95 {p95 / 1e6:.3f}, p99 {p99 / 1e6:.3f}, "
          f"min {low / 1e6:.3f}, max {high / 1e6:.3f}")


def population_bins(rows, population):
    unknown = sum(not r.get(population, '').strip() for r in rows)
    if unknown:
        print(f'    {unknown} samples have unknown population; excluded from population bins')
        rows = [r for r in rows if r.get(population, '').strip()]
    if not rows:
        return
    width = max(1, math.ceil(max(int(r[population]) for r in rows) / 10))
    groups = defaultdict(list)
    for row in rows:
        n = int(row[population])
        groups[max(0, n - 1) // width].append(row)
    print("    population       samples    mean ms  median ms")
    for _, group in sorted(groups.items()):
        counts = [int(r[population]) for r in group]
        values = [int(r['elapsed_ns']) / 1e6 for r in group]
        label = f"{min(counts)}..{max(counts)}"
        print(f"    {label:16} {len(values):7d} {statistics.mean(values):10.3f} "
              f"{statistics.median(values):10.3f}")


def collection(path):
    # Read selected regular files in place. Never extract archive paths.
    wanted = lambda n: (PurePosixPath(n).name in
                       {'run.json', 'creation.csv', 'queries.csv', 'deletion.csv', 'summary.json'}
                       or PurePosixPath(n).name.endswith(('.txt', '.stderr')))
    files = {}
    if path.is_dir():
        for p in sorted(path.rglob('*')):
            if p.is_file() and not p.is_symlink() and wanted(p.name):
                files[p.relative_to(path).as_posix()] = p.read_text()
    elif zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            for entry in archive.infolist():
                if not entry.is_dir() and wanted(entry.filename):
                    key = PurePosixPath(entry.filename).as_posix()
                    if key in files:
                        raise ValueError(f"duplicate archive member: {entry.filename}")
                    files[key] = archive.read(entry).decode('utf-8', errors='replace')
    else:
        with tarfile.open(path) as archive:
            for entry in archive:
                if entry.isfile() and wanted(entry.name):
                    key = PurePosixPath(entry.name).as_posix()
                    if key in files:
                        raise ValueError(f"duplicate archive member: {entry.name}")
                    files[key] = archive.extractfile(entry).read().decode('utf-8', errors='replace')
    return files


def report_run(base, files, all_checkpoints):
    def name(leaf):
        return str(PurePosixPath(base) / leaf)

    def rows(leaf):
        return list(csv.DictReader(io.StringIO(files.get(name(leaf), ''))))

    info = json.loads(files[name('run.json')]) if name('run.json') in files else {}
    args = info.get('arguments', {})
    print(f"\nRun: {base or '.'}")
    print(f"  status: {info.get('status', 'unknown')}; "
          f"cleanup pending: {info.get('cleanup_pending', 'unknown')}")
    kernel = info.get('kern.version')
    if kernel:
        print('  kernel: ' + kernel.strip().replace('\n', ' '))
    print('  settings: ' + ', '.join(f'{k}={args[k]}' for k in
          ('max_jails', 'list_every', 'repeats', 'warmups', 'cleanup_order', 'keep_jails') if k in args))
    if info.get('error'):
        print('  ERROR: ' + str(info['error']))
    if info.get('stderr'):
        print('  stderr: ' + str(info['stderr']).strip())

    creation = rows('creation.csv')
    if creation:
        timing('creation commands', [int(r['elapsed_ns']) for r in creation])
        population_bins(creation, 'created_jails')

    queries = rows('queries.csv')
    if queries:
        groups = defaultdict(list)
        for row in queries:
            groups[(int(row['created_jails']), row['operation'])].append(int(row['elapsed_ns']))
        checkpoints = sorted({n for n, _ in groups})
        selected = set(checkpoints)
        if not all_checkpoints and len(checkpoints) > 12:
            selected = {min(checkpoints, key=lambda n: abs(n - i * checkpoints[-1] / 10))
                        for i in range(11)}
            selected.add(checkpoints[0])
            if 1 in checkpoints:
                selected.add(1)
        print('  Queries (each time is a complete listing or lookup batch):')
        print('    created operation          samples   median ms      min ms      max ms')
        for (n, op), values in sorted(groups.items()):
            if n in selected:
                print(f"    {n:7d} {op:18} {len(values):7d} "
                      f"{statistics.median(values) / 1e6:11.3f} "
                      f"{min(values) / 1e6:11.3f} {max(values) / 1e6:11.3f}")
        if len(selected) < len(checkpoints):
            print(f'    Showing {len(selected)}/{len(checkpoints)} checkpoints; use --all-checkpoints for all.')

    prefix = name('cleanup') + '/'
    attempts = sorted({str(PurePosixPath(n).parent) for n in files
                       if n.startswith(prefix) and n.endswith(('/deletion.csv', '/summary.json'))})
    for attempt in attempts:
        print(f'  Cleanup attempt: {PurePosixPath(attempt).name}')
        deletion = list(csv.DictReader(io.StringIO(files.get(attempt + '/deletion.csv', ''))))
        print('    statuses: ' + ', '.join(f'{k}={v}' for k, v in sorted(Counter(r['status'] for r in deletion).items())))
        # Skips and failed commands are not successful deletion latency samples.
        removed = [r for r in deletion if r['status'] == 'removed']
        timing('successful removal commands', [int(r['elapsed_ns']) for r in removed])
        population_bins(removed, 'tracked_live_before')
        summary_name = attempt + '/summary.json'
        if summary_name not in files:
            print('    WARNING: missing summary.json; cleanup may be incomplete')
            continue
        summary = json.loads(files[summary_name])
        print(f"    order: {summary.get('order', 'unknown')}; "
              f"drain complete: {summary.get('drain_complete', 'unknown')}; "
              f"failures: {len(summary.get('failures', []))}")
        for key in ('initial_snapshot_ns', 'command_total_ns', 'verification_total_ns',
                    'removal_phase_ns', 'drain_observation_ns', 'total_ns'):
            if key in summary:
                print(f"    {key.removesuffix('_ns')}: {summary[key] / 1e9:.3f} s")
        for key in ('failures', 'remaining_prisons', 'drain_error'):
            if summary.get(key):
                print(f'    WARNING {key}: {summary[key]}')


def report_traces(files):
    for name, body in sorted(files.items()):
        filename = PurePosixPath(name).name
        if filename.endswith('.stderr'):
            print(f"\nDiagnostics: {name}: {'NONEMPTY' if body.strip() else 'empty'}")
            if body.strip():
                print(body.strip())
            continue
        if not filename.endswith('.txt') or not filename.startswith(('jls-', 'enum-', 'lock-', 'cleanup-')):
            continue
        print(f'\nTrace: {name}')
        entries, returns = {}, {}
        for line in body.splitlines():
            match = re.fullmatch(r'(\S+) (\S+) (entries|returns)=(\d+)', line)
            if match:
                exe, func, kind, count = match.groups()
                (entries if kind == 'entries' else returns)[(exe, func)] = int(count)
            match = re.fullmatch(r'(.+?) (elapsed_ns|cpu_ns|total_ns|calls|events|cpu_gt_elapsed_samples)=(\d+)', line)
            if match:
                label, metric, value = match.groups()
                if metric.endswith('_ns'):
                    print(f"  {label} {metric.removesuffix('_ns')}: {int(value) / 1e6:.3f} ms")
                else:
                    print(f'  {label} {metric}: {value}')
                if metric == 'cpu_gt_elapsed_samples' and int(value):
                    print('  WARNING: invalid CPU samples; do not attribute CPU time')
        for key in sorted(entries.keys() | returns.keys()):
            a, b = entries.get(key, 0), returns.get(key, 0)
            print(f'  {key[0]} {key[1]}: entries={a}, returns={b}')
            if a != b:
                print('  WARNING: entry/return count mismatch')
        for label, value in re.findall(r'^(.+?) elapsed_ns=(\d+)$', body, re.M):
            calls = re.search(r'^' + re.escape(label) + r' calls=(\d+)$', body, re.M)
            count = int(calls[1]) if calls else returns.get(tuple(label.split()), 0)
            if count:
                print(f'  {label} mean elapsed: {int(value) / count / 1000:.3f} us/call')
        if filename.startswith(('jls-', 'enum-')):
            for line in body.splitlines():
                if line.startswith('jail_get calls:'):
                    print('  ' + line)
            wall = re.search(r'jail_get total elapsed ns:\s*(\d+)', body)
            cpu = re.search(r'jail_get total on-CPU ns:\s*(\d+)', body)
            for label, match in [('elapsed', wall), ('on-CPU', cpu)]:
                if match:
                    print(f'  jail_get {label}: {int(match[1]) / 1e6:.3f} ms')
            if wall and cpu and int(cpu[1]) > int(wall[1]):
                print('  WARNING: on-CPU time exceeds elapsed time')
        if 'allprison waits:' in body and not re.search(r'\bevents=\d+|\b(?:sx-block|sx-spin)\b', body):
            print('  No instrumented lock waits recorded; this does not measure lock hold time.')
        if not body.strip():
            print('  WARNING: empty report')


parser = argparse.ArgumentParser(description='Summarize jailbench directories, tar archives, or zip archives; read-only.')
parser.add_argument('inputs', nargs='+', type=Path)
parser.add_argument('--all-checkpoints', action='store_true')
args = parser.parse_args()
failed = False
for source in args.inputs:
    try:
        files = collection(source)
        bases = sorted({str(PurePosixPath(n).parent) for n in files
                        if PurePosixPath(n).name in {'run.json', 'creation.csv', 'queries.csv'}})
        traces = any(PurePosixPath(n).name.startswith(('cleanup-', 'jls-', 'enum-', 'lock-'))
                     and n.endswith('.txt') for n in files)
        if not bases and not traces:
            raise ValueError('no benchmark runs or trace reports found')
        print(f'Collection: {source}')
        for base in bases:
            report_run(base, files, args.all_checkpoints)
        report_traces(files)
    except (OSError, ValueError, KeyError, TypeError, csv.Error, tarfile.TarError, zipfile.BadZipFile) as exc:
        print(f'ERROR {source}: {exc}', file=sys.stderr)
        failed = True
print('\nNotes: command timings include process startup; query timings are batch totals.')
print('Percentiles use nearest rank. Cleanup phases and inclusive trace timings overlap; do not sum them.')
print('Keep instrumented and uninstrumented trials separate. Labels do not establish indexed/unindexed status.')
sys.exit(1 if failed else 0)
