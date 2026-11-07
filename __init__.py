import json
import tarfile
import zipfile
from .core import Rehearsal

TOOLS = {
    'restore_inspect': ('Inspect an untrusted ZIP or tar (plain, gzip, bzip2, xz) backup and fingerprint it without extracting files.', {'archive_path': {'type': 'string'}}, ['archive_path']),
    'restore_list_rehearsals': ('List local rehearsal folders without inspecting their contents. Folder presence does not prove a restore completed.', {}, []),
    'restore_rehearse': ('Restore an inspected ZIP or tar archive into a new isolated directory and verify bytes (CRC for ZIP only). Optional expected_sha256 maps paths to trusted hashes; every file must match.', {'archive_path': {'type': 'string'}, 'fingerprint': {'type': 'string'}, 'expected_sha256': {'type': 'object', 'additionalProperties': {'type': 'string'}}}, ['archive_path', 'fingerprint']),
}

def invoke(name, args):
    from plugins.plugin_storage import plugin_data_dir
    try:
        return json.dumps(getattr(Rehearsal(plugin_data_dir('restore-rehearsal')), name.removeprefix('restore_'))(**args))
    except (ValueError, TypeError, OSError, KeyError, RuntimeError, EOFError, zipfile.BadZipFile, tarfile.TarError) as exc:
        return json.dumps({'error': str(exc)})

def register(ctx):
    for name, (description, properties, required) in TOOLS.items():
        ctx.register_tool(name=name, toolset='restore_rehearsal', schema={'name': name, 'description': description,
            'parameters': {'type': 'object', 'properties': properties, 'required': required, 'additionalProperties': False}},
            handler=lambda args, _name=name, **kwargs: invoke(_name, args))
