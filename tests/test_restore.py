import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location('restore_core', Path(__file__).parents[1] / 'core.py')
core = importlib.util.module_from_spec(spec)
spec.loader.exec_module(core)

class RestoreTests(unittest.TestCase):
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

if __name__ == '__main__':
    unittest.main()
