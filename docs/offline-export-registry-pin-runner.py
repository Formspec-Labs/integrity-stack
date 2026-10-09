"""Run the granted offline CLI tests with source pins and owned-group cleanup."""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time
import tomllib
from datetime import datetime, timezone

root = Path('/Users/mikewolfd/Work/formspec-stack')
manifest = root / 'integrity-stack/crates/integrity-verify-cli/Cargo.toml'
target = Path('/tmp/formspec-exact-source-composition-target-20261009-v1')
report_dir = root / 'thoughts/plans/benefits-scenarios/execution/reports/integrity-stack/offline-export-registry-pin'
report_dir.mkdir(parents=True, exist_ok=True)
stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
log_path = report_dir / f'native-cli-tests-{stamp}.log'
receipt_path = report_dir / f'native-cli-tests-{stamp}.json'

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

frozen = root / 'integrity-stack/docs/offline-export-registry-pin-handoff-v2.json'
assert sha(frozen) == '078c2774cc811f28721df3d32a9bd4e5c66a6a5808b583b3dd665a98c37eea77'
for relative, digest in json.loads(frozen.read_text())['files'].items():
    assert sha(root / 'integrity-stack' / relative) == digest, relative

# All local path-dependency source files, owning workspace manifests and locks.
files = {root / '.cargo/config.toml', frozen, Path(__file__).resolve()}
seen = set()
def visit(path):
    path = path.resolve()
    if path in seen:
        return
    seen.add(path)
    data = tomllib.loads(path.read_text())
    names = subprocess.check_output(['rg', '--files', '--hidden', str(path.parent)], text=True).splitlines()
    files.update(Path(name) for name in names if Path(name).is_file())
    for parent in [path.parent, *path.parent.parents]:
        candidate = parent / 'Cargo.toml'
        if candidate.is_file():
            files.add(candidate)
        lock = parent / 'Cargo.lock'
        if lock.is_file():
            files.add(lock)
        if parent == root:
            break
    def dependencies(value):
        if not isinstance(value, dict):
            return
        for key, item in value.items():
            if key in ('dependencies', 'dev-dependencies', 'build-dependencies'):
                for dep in item.values():
                    if isinstance(dep, dict) and 'path' in dep:
                        visit(path.parent / dep['path'] / 'Cargo.toml')
            elif isinstance(item, dict):
                dependencies(item)
    dependencies(data)
visit(manifest)
# The runner/receipt directory is outside the dependency source trees.
before = {str(path.relative_to(root)): sha(path) for path in sorted(files)}
preserved = [root / '.cargo-target/debug/integrity-verify'] + [target / 'debug' / name for name in ('wos-server', 'formspec-server', 'trellis-server')]
preserved_before = {str(path): sha(path) for path in preserved if path.is_file()}
command = ['cargo', 'test', '--offline', '--locked', '-j', '1', '--manifest-path', str(manifest)]
env = os.environ.copy()
env.update(CARGO_BUILD_JOBS='1', CARGO_TARGET_DIR=str(target))

def group_members(pgid):
    output = subprocess.check_output(['ps', '-axo', 'pid=,pgid=,comm='], text=True)
    return [line.strip() for line in output.splitlines() if len(line.split()) >= 2 and line.split()[1] == str(pgid)]

started = time.monotonic()
error = None
timed_out = False
cleanup_errors = []
with log_path.open('wb') as log:
    child = subprocess.Popen(command, cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    pgid = child.pid
    print(json.dumps({'started': True, 'pgid': pgid, 'log': str(log_path), 'receipt': str(receipt_path)}), flush=True)
    try:
        child.wait(timeout=600)
    except subprocess.TimeoutExpired:
        timed_out = True
    except BaseException as exc:
        error = repr(exc)
    finally:
        # Reap the owned leader if it has exited before checking its group.
        child.poll()
        try:
            members = group_members(pgid)
            if members:
                os.killpg(pgid, signal.SIGTERM)
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
                if group_members(pgid):
                    os.killpg(pgid, signal.SIGKILL)
        except (OSError, subprocess.SubprocessError) as exc:
            cleanup_errors.append(repr(exc))
        try:
            child.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired) as exc:
            cleanup_errors.append(repr(exc))
        try:
            remaining = group_members(pgid)
        except (OSError, subprocess.SubprocessError) as exc:
            remaining = None
            cleanup_errors.append(repr(exc))
after = {str(path.relative_to(root)): sha(path) for path in sorted(files)}
preserved_after = {str(path): sha(path) for path in preserved if path.is_file()}
receipt = {'command': command, 'cwd': str(root), 'targetDir': str(target),
    'cacheRationale': 'Reuse retained 6GiB Core composition target: compatible named Integrity/Trellis/WOS fingerprints exist; Cargo validates precise versions/features/config. No dependency-cache copy/deletion or installed CLI target used.',
    'wallCapSeconds': 600, 'elapsedSeconds': time.monotonic() - started,
    'exitCode': child.returncode, 'timedOut': timed_out, 'error': error, 'processGroup': pgid,
    'remainingGroupMembers': remaining, 'cleanupErrors': cleanup_errors,
    'cleanupConfirmed': remaining == [] and not cleanup_errors and child.returncode is not None,
    'sourcePins': before, 'sourcesUnchanged': before == after,
    'changedSourcePins': {key: {'before': before.get(key), 'after': after.get(key)} for key in before.keys() | after.keys() if before.get(key) != after.get(key)},
    'preservedArtifacts': preserved_before, 'preservedArtifactsUnchanged': preserved_before == preserved_after,
    'log': str(log_path), 'logSha256': sha(log_path),
    'limits': 'Synthetic native CLI tests only; no actual D1 archive, live calls, keys, service changes or shared adoption.'}
receipt_path.write_text(json.dumps(receipt, indent=2) + '\n')
print(json.dumps({'receipt': str(receipt_path), 'receiptSha256': sha(receipt_path),
    'exitCode': child.returncode, 'timedOut': timed_out, 'cleanupConfirmed': receipt['cleanupConfirmed'],
    'sourcesUnchanged': receipt['sourcesUnchanged'], 'preservedArtifactsUnchanged': receipt['preservedArtifactsUnchanged']}), flush=True)
