import importlib.util
import struct
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "java-decompiler" / "scripts" / "decompile_java.py"


def load_module():
    spec = importlib.util.spec_from_file_location("decompile_java", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DetectArchiveTypeTests(unittest.TestCase):
    def setUp(self):
        self.mod = load_module()

    def test_class_file_detected(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "Test.class"
            target.write_bytes(struct.pack(">IHH", 0xCAFEBABE, 0, 52))
            self.assertEqual(self.mod.detect_archive_type(target), "class")

    def test_macho_fat_binary_not_detected_as_class(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "universal_bin"
            # 0xCAFEBABE followed by nfat_arch=2 (major version would unpack as 2 < 45)
            target.write_bytes(struct.pack(">II", 0xCAFEBABE, 2) + b"\x00" * 100)
            self.assertEqual(self.mod.detect_archive_type(target), "unknown")


if __name__ == "__main__":
    unittest.main()
