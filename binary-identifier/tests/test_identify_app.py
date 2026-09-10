import importlib.util
import io
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "binary-identifier" / "scripts" / "identify_app.py"


def load_module():
    spec = importlib.util.spec_from_file_location("identify_app", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def create_macho_fat_binary(extra_payload: bytes = b"") -> bytes:
    """Construct a minimal valid Mach-O universal (fat) binary with 2 architectures."""
    # fat_header: magic (0xCAFEBABE), nfat_arch (2)
    header = struct.pack(">II", 0xCAFEBABE, 2)

    # slice 1: x86_64 at offset 4096, size 512
    # cputype (0x01000007), cpusubtype (0x80000003), offset (4096), size (512), align (12)
    arch1 = struct.pack(">IIIII", 0x01000007, 0x80000003, 4096, 512, 12)

    # slice 2: arm64 at offset 8192, size 512 + len(extra_payload)
    # cputype (0x0100000c), cpusubtype (0x00000000), offset (8192), size (512 + len(extra_payload)), align (14)
    arch2 = struct.pack(">IIIII", 0x0100000C, 0x00000000, 8192, 512 + len(extra_payload), 14)

    data = bytearray(header + arch1 + arch2)
    # Pad up to offset 4096
    data.extend(b"\x00" * (4096 - len(data)))
    # Slice 1: Mach-O 64-bit little endian magic (0xFEEDFACF -> b'\xcf\xfa\xed\xfe')
    data.extend(b"\xcf\xfa\xed\xfe" + b"\x00" * 508)

    # Pad up to offset 8192
    data.extend(b"\x00" * (8192 - len(data)))
    # Slice 2: Mach-O 64-bit little endian magic + extra payload
    data.extend(b"\xcf\xfa\xed\xfe" + extra_payload + b"\x00" * max(0, 508 - len(extra_payload)))

    return bytes(data)


def create_java_class_file() -> bytes:
    """Construct a minimal Java 8 class file (major=52, minor=0)."""
    # magic 0xCAFEBABE, minor 0, major 52
    return struct.pack(">IHH", 0xCAFEBABE, 0, 52) + b"\x00\x01\x00\x00"


class IdentifyAppTests(unittest.TestCase):
    def setUp(self):
        self.mod = load_module()

    def test_macho_fat_binary_not_identified_as_java(self):
        fat_bin = create_macho_fat_binary()
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "universal_bin"
            target.write_bytes(fat_bin)
            results = self.mod.identify(target)

        self.assertIsNotNone(results, "identify() should return the results dict")
        self.assertNotIn("Java", results["Language/Compiler"])
        self.assertNotIn("Java class file (0xCAFEBABE)", results["Misc/Indicators"])
        self.assertTrue(
            any("Mach-O universal (fat) binary" in ind for ind in results["Misc/Indicators"]),
            f"Expected Mach-O fat binary indicator, got: {results['Misc/Indicators']}",
        )

    def test_macho_fat_python_binary_detected_as_python(self):
        fat_bin = create_macho_fat_binary(extra_payload=b"Py_Initialize\x00libpython3.12.dylib")
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "python3"
            target.write_bytes(fat_bin)
            results = self.mod.identify(target)

        self.assertIsNotNone(results)
        self.assertIn("Python", results["Language/Compiler"])
        self.assertNotIn("Java", results["Language/Compiler"])
        self.assertNotIn("Java class file (0xCAFEBABE)", results["Misc/Indicators"])

    def test_java_class_file_identified_as_java(self):
        class_bytes = create_java_class_file()
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "Test.class"
            target.write_bytes(class_bytes)
            results = self.mod.identify(target)

        self.assertIsNotNone(results)
        self.assertIn("Java", results["Language/Compiler"])
        self.assertIn("Java class file (0xCAFEBABE)", results["Misc/Indicators"])

    def test_macho_thin_64bit_binary_detected(self):
        thin_bytes = b"\xcf\xfa\xed\xfe" + b"\x00" * 100
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "thin_bin"
            target.write_bytes(thin_bytes)
            results = self.mod.identify(target)

        self.assertIsNotNone(results)
        self.assertNotIn("Java", results["Language/Compiler"])
        self.assertTrue(
            any("Mach-O" in ind for ind in results["Misc/Indicators"]),
            f"Expected Mach-O indicator, got: {results['Misc/Indicators']}",
        )

    def test_java_jar_archive_detected(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
            zf.writestr("com/example/Main.class", create_java_class_file())
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "app.jar"
            target.write_bytes(buf.getvalue())
            results = self.mod.identify(target)

        self.assertIsNotNone(results)
        self.assertIn("Java", results["Language/Compiler"])
        self.assertIn("Java JAR archive", results["Misc/Indicators"])


if __name__ == "__main__":
    unittest.main()
