"""Pure AST tests: never import or execute a native probe entrypoint."""
import ast
from pathlib import Path
import re
import unittest


class TrustedVersionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = Path(__file__).resolve().parents[1] / "bin/phase5-trusted-probe"
        function = next(node for node in ast.parse(source.read_text()).body
                        if isinstance(node, ast.FunctionDef) and node.name == "version_at_or_above")
        scope = {"re": re, "MINIMUM_VERSION": "codex-cli 0.145.0"}
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), "exec"), scope)
        cls.compare = staticmethod(scope["version_at_or_above"])

    def test_invalid_before_ordering(self):
        for value in (None, 123, True, {}, "codex-cli 1.0.0-.",
                      "codex-cli 0.146.0-alpha..18", "codex-cli 1.0.0-alpha.",
                      "codex-cli " + "9" * 5000 + ".0", "codex-cli 1.0.0\n"):
            with self.subTest(kind=type(value).__name__):
                self.assertFalse(self.compare(value))
                self.assertFalse(self.compare("codex-cli 2.0.0", value))

    def test_valid_comparisons(self):
        self.assertTrue(self.compare("codex-cli 0.146.0-alpha.18"))
        self.assertFalse(self.compare("codex-cli 0.144.0"))
        self.assertFalse(self.compare("codex-cli 1.0.0-alpha.18", "codex-cli 1.0.0"))
        self.assertTrue(self.compare("codex-cli 1.0.0", "codex-cli 1.0.0-alpha.18"))


if __name__ == "__main__":
    unittest.main()
