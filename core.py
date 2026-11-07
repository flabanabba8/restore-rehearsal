"""Restore a ZIP or tar archive to a unique sandbox and report integrity evidence."""
import hashlib
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import tarfile
import uuid
import zipfile

PRIVATE = {'.ssh', '.gnupg', '.aws', '.azure', '.codex', '.docker', '.kube', '.pki', '.config', '.hermes'}
MAX_BYTES = 2 * 1024**3
MAX_FILES = 10000


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def safe_source(value):
    path = Path(value).expanduser()
    if path.is_symlink() or any(x.casefold() in PRIVATE for x in path.parts):
        raise ValueError('Private paths and symlink inputs are unsupported')
    path = path.resolve(strict=True)
    if any(x.casefold() in PRIVATE for x in path.parts) or not path.is_file():
        raise ValueError('Choose an archive outside private configuration')
    return path


class TarEntry:
    """Presents a tar member with the attributes the ZIP checks use; links and special files get types the checks reject."""
    def __init__(self, member):
        self.member = member
        name = member.name[2:] if member.name.startswith('./') else member.name
        self.filename = name.rstrip('/') + ('/' if member.isdir() else '') if name not in ('', '.') else name
        self.file_size = 0 if member.isdir() else member.size
        kind = stat.S_IFDIR if member.isdir() else stat.S_IFREG if member.isreg() else stat.S_IFLNK if (member.issym() or member.islnk()) else stat.S_IFCHR
        self.external_attr = (kind | (member.mode & 0o777)) << 16
        self.flag_bits = 0
        self.CRC = None
    def is_dir(self): return self.member.isdir()


def open_archive(path):
    """Return (entries, open_member, close, kind) for a ZIP or a tar (plain, gzip, bzip2, xz)."""
    with path.open('rb') as f: magic = f.read(4)
    if magic[:2] == b'PK':
        z = zipfile.ZipFile(path)
        return z.infolist(), z.open, z.close, 'zip'
    try:
        tf = tarfile.open(path, 'r:*')
    except tarfile.TarError:
        raise ValueError('Choose a ZIP or tar archive (plain, gzip, bzip2 or xz)') from None
    infos = []
    for member in tf:
        infos.append(TarEntry(member))
        if len(infos) > MAX_FILES + 1:
            tf.close(); raise ValueError('Archive exceeds restore limits')
    return infos, (lambda info: tf.extractfile(info.member)), tf.close, 'tar'


def entries(infos):
    files, directories, explicit, components, file_keys, total = [], [], set(), {}, set(), 0
    for info in infos:
        name = info.filename
        path = PurePosixPath(name)
        mode = info.external_attr >> 16
        canonical = path.as_posix()
        if ('\\' in name or name.startswith('/') or not path.parts or
            name != canonical + ('/' if info.is_dir() else '') or
            any(x in ('.', '..') or ':' in x for x in path.parts) or
            stat.S_ISLNK(mode) or (mode and stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR)) or info.flag_bits & 1 or
            (info.is_dir() and info.file_size)):
            raise ValueError('Unsafe path, link, special file, or encrypted entry')
        key = canonical.casefold()
        if key in explicit:
            raise ValueError('Duplicate or case-colliding paths')
        explicit.add(key)
        for component in [path, *path.parents]:
            component_name = str(component)
            if component_name == '.': continue
            folded = component_name.casefold()
            if folded in components and components[folded] != component_name:
                raise ValueError('Duplicate or case-colliding paths')
            components[folded] = component_name
        if len(explicit) > MAX_FILES: raise ValueError('Archive exceeds restore limits')
        if info.is_dir():
            directories.append(info)
        else:
            file_keys.add(key)
            total += info.file_size
            if total > MAX_BYTES: raise ValueError('Archive exceeds restore limits')
            files.append(info)
    if not files and not directories:
        raise ValueError('No files or directories to restore')
    for info in files + directories:
        if any(str(parent).casefold() in file_keys for parent in PurePosixPath(info.filename).parents if str(parent) != '.'):
            raise ValueError('File path collides with a parent path')
    return files, directories, total


class Rehearsal:
    def __init__(self, root):
        self.root = Path(root).resolve()

    def inspect(self, archive_path):
        path = safe_source(archive_path)
        fingerprint = digest(path)
        infos, _, close, kind = open_archive(path)
        try:
            files, directories, total = entries(infos)
            result = [{'path': i.filename, 'bytes': i.file_size, 'crc32': (f'{i.CRC:08x}' if i.CRC is not None else None)} for i in files]
        finally:
            close()
        if digest(path) != fingerprint:
            raise ValueError('Archive changed while inspecting')
        return {'fingerprint': fingerprint, 'kind': kind, 'files': result, 'directories': [i.filename for i in directories], 'total_bytes': total}

    def rehearse(self, archive_path, fingerprint, expected_sha256=None):
        path = safe_source(archive_path)
        if digest(path) != fingerprint:
            raise ValueError('Archive changed; inspect it again')
        if expected_sha256 is not None and (not isinstance(expected_sha256, dict) or any(not isinstance(k, str) or not isinstance(v, str) or len(v) != 64 or any(c not in '0123456789abcdef' for c in v) for k, v in expected_sha256.items())):
            raise ValueError('Expected hashes must be lowercase SHA-256 strings keyed by path')
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        target = self.root / uuid.uuid4().hex
        target.mkdir(mode=0o700)
        try:
            hashes = {}
            infos, open_member, close, kind = open_archive(path)
            try:
                files, directories, total = entries(infos)
                if shutil.disk_usage(target).free < total + 16 * 1024**2:
                    raise ValueError('Not enough free space for restore')
                if expected_sha256 is not None and set(expected_sha256) != {i.filename for i in files}:
                    raise ValueError('Expected hash list must cover exactly all archive files')
                for info in directories:
                    (target / info.filename).mkdir(parents=True, exist_ok=True)
                for info in files:
                    out = target / info.filename
                    out.parent.mkdir(parents=True, exist_ok=True)
                    with open_member(info) as src, os.fdopen(os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as dst:
                        shutil.copyfileobj(src, dst, 1024 * 1024)
                    hashes[info.filename] = digest(out)
                    if expected_sha256 is not None and hashes[info.filename] != expected_sha256[info.filename]:
                        raise ValueError('Restored content does not match trusted hashes')
            finally:
                close()
            if digest(path) != fingerprint:
                raise ValueError('Archive changed during restore')
        except BaseException:
            shutil.rmtree(target, ignore_errors=True)
            raise
        return {'restored_path': str(target), 'files': len(hashes), 'directories': len(directories), 'sha256': hashes,
                'archive_kind': kind, 'crc_verified': kind == 'zip', 'trusted_hashes_verified': expected_sha256 is not None}

    def list_rehearsals(self):
        if not self.root.exists(): return {'rehearsals': [], 'notice': 'Folder presence does not prove a restore completed or remains intact.'}
        found = []
        for path in self.root.iterdir():
            if len(path.name) != 32 or any(c not in '0123456789abcdef' for c in path.name): continue
            if path.is_symlink() or not path.is_dir(): continue
            found.append({'rehearsal_id': path.name, 'restored_path': str(path), 'status': 'unverified'})
            if len(found) > 1000: raise ValueError('More than 1,000 rehearsal folders; narrow the workspace')
        found.sort(key=lambda row: row['rehearsal_id'])
        return {'rehearsals': found, 'notice': 'Folder presence does not prove a restore completed or remains intact. Inspect the files before use.'}
