import hashlib
import importlib.util
import os
from pathlib import Path
import io
import tarfile
import tempfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location('restore_core', Path(__file__).parents[1] / 'core.py')
core = importlib.util.module_from_spec(spec)
spec.loader.exec_module(core)

class RestoreTests(unittest.TestCase):
    def test_mixed_case_private_directory_is_rejected(self):
        folder=self.root/'.CoDeX';folder.mkdir();source=folder/'fixture.zip';source.write_bytes(b'fixture')
        with self.assertRaises(ValueError):core.safe_source(str(source))

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir='/tmp')
        self.root = Path(self.tmp.name)
        self.archive = self.root / 'backup.zip'
        self.plugin = core.Rehearsal(self.root / 'restore')
        self.write({'dir/file.txt': 'data'})

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, entries):
        with zipfile.ZipFile(self.archive, 'w') as z:
            for name, text in entries.items():
                z.writestr(name, text)

    def test_restore_and_trusted_hashes(self):
        info = self.plugin.inspect(str(self.archive))
        hashes = {'dir/file.txt': hashlib.sha256(b'data').hexdigest()}
        result = self.plugin.rehearse(str(self.archive), info['fingerprint'], hashes)
        self.assertTrue(result['crc_verified'])
        self.assertTrue(result['trusted_hashes_verified'])
        self.assertEqual((Path(result['restored_path']) / 'dir/file.txt').read_text(), 'data')
        self.assertTrue(self.archive.exists())

    def test_restored_files_are_private_under_permissive_umask(self):
        info = self.plugin.inspect(str(self.archive))
        previous = os.umask(0)
        try:
            result = self.plugin.rehearse(str(self.archive), info['fingerprint'])
            self.assertEqual((Path(result['restored_path']) / 'dir/file.txt').stat().st_mode & 0o777, 0o600)
        finally:
            os.umask(previous)

    def test_recover_folders_without_claiming_success(self):
        info = self.plugin.inspect(str(self.archive))
        result = self.plugin.rehearse(str(self.archive), info['fingerprint'])
        parent = self.root/'restore'
        incomplete = parent/('a'*32); incomplete.mkdir()
        (parent/('b'*32)).symlink_to(incomplete)
        rows = self.plugin.list_rehearsals()['rehearsals']
        self.assertEqual(len(rows), 2)
        self.assertIn(result['restored_path'], [row['restored_path'] for row in rows])
        self.assertTrue(all(row['status'] == 'unverified' for row in rows))
        self.assertNotIn('file.txt', str(rows))

    def test_bad_hash_removes_partial_restore(self):
        info = self.plugin.inspect(str(self.archive))
        with self.assertRaisesRegex(ValueError, 'does not match'):
            self.plugin.rehearse(str(self.archive), info['fingerprint'], {'dir/file.txt': '0' * 64})
        self.assertEqual(list((self.root / 'restore').iterdir()), [])

    def test_stale_and_unsafe(self):
        info = self.plugin.inspect(str(self.archive))
        self.write({'../outside': 'bad'})
        with self.assertRaisesRegex(ValueError, 'changed'):
            self.plugin.rehearse(str(self.archive), info['fingerprint'])
        with self.assertRaisesRegex(ValueError, 'Unsafe'):
            self.plugin.inspect(str(self.archive))
        self.write({'a': 'one', 'a/b': 'two'})
        with self.assertRaisesRegex(ValueError, 'parent'):
            self.plugin.inspect(str(self.archive))

    def test_empty_directory_and_implicit_case_collision(self):
        self.write({'dir/': '', 'dir/file.txt': 'data', 'empty/': ''})
        info = self.plugin.inspect(str(self.archive))
        result = self.plugin.rehearse(str(self.archive), info['fingerprint'])
        self.assertTrue((Path(result['restored_path']) / 'empty').is_dir())
        self.write({'Folder/a': 'one', 'folder/b': 'two'})
        with self.assertRaisesRegex(ValueError, 'case'):
            self.plugin.inspect(str(self.archive))

    def test_missing_expected_entries(self):
        info = self.plugin.inspect(str(self.archive))
        with self.assertRaisesRegex(ValueError, 'exactly all'):
            self.plugin.rehearse(str(self.archive), info['fingerprint'], {})


class TarTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir='/tmp'); self.root = Path(self.tmp.name)
        self.plugin = core.Rehearsal(self.root / 'restore')
    def tearDown(self): self.tmp.cleanup()

    def make(self, members, mode='w:gz', name='backup.tar.gz'):
        path = self.root / name
        with tarfile.open(path, mode) as tf:
            for member, data in members:
                tf.addfile(member, io.BytesIO(data) if data is not None else None)
        return str(path)

    def regular(self, name, data=b'data'):
        info = tarfile.TarInfo(name); info.size = len(data); info.mode = 0o644; return info, data

    def test_tar_gz_is_inspected_and_restored_with_hashes(self):
        directory = tarfile.TarInfo('proj'); directory.type = tarfile.DIRTYPE; directory.mode = 0o755
        path = self.make([(directory, None), self.regular('proj/a.txt', b'alpha'), self.regular('./proj/b.txt', b'beta')])
        seen = self.plugin.inspect(path)
        self.assertEqual(seen['kind'], 'tar'); self.assertEqual(sorted(f['path'] for f in seen['files']), ['proj/a.txt', 'proj/b.txt'])
        self.assertIsNone(seen['files'][0]['crc32'])
        done = self.plugin.rehearse(path, seen['fingerprint'])
        self.assertEqual(done['sha256']['proj/a.txt'], hashlib.sha256(b'alpha').hexdigest())
        self.assertEqual(done['archive_kind'], 'tar'); self.assertFalse(done['crc_verified'])
        self.assertEqual((Path(done['restored_path']) / 'proj' / 'b.txt').read_bytes(), b'beta')

    def test_unsafe_tar_members_are_refused(self):
        symlink = tarfile.TarInfo('proj/link'); symlink.type = tarfile.SYMTYPE; symlink.linkname = '/etc/passwd'
        hardlink = tarfile.TarInfo('proj/hard'); hardlink.type = tarfile.LNKTYPE; hardlink.linkname = 'proj/a.txt'
        fifo = tarfile.TarInfo('proj/pipe'); fifo.type = tarfile.FIFOTYPE
        for bad in ([self.regular('../escape.txt')], [self.regular('/abs.txt')], [(symlink, None)], [self.regular('proj/a.txt'), (hardlink, None)], [(fifo, None)],
                    [self.regular('proj/a.txt'), self.regular('PROJ/A.txt')]):
            with self.assertRaises(ValueError): self.plugin.inspect(self.make(bad))
        self.assertFalse((self.root / 'escape.txt').exists())

    def test_non_archive_and_changed_archive_are_refused(self):
        junk = self.root / 'x.tar.gz'; junk.write_bytes(b'not an archive at all')
        with self.assertRaises(ValueError): self.plugin.inspect(str(junk))
        path = self.make([self.regular('a.txt')]); seen = self.plugin.inspect(path)
        self.make([self.regular('a.txt', b'different content')])
        with self.assertRaisesRegex(ValueError, 'changed'): self.plugin.rehearse(path, seen['fingerprint'])

if __name__ == '__main__':
    unittest.main()
