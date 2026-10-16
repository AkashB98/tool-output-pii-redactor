"""Minimal hermetic test runner (stdlib only, no pytest needed).

Discovers test_*.py in this directory, runs every test_* function,
reports failures. Exit 0 = all green.
"""

import inspect
import os
import pkgutil
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tests  # noqa: E402  (the package)


def main() -> int:
    modules = []
    for info in pkgutil.iter_modules(tests.__path__):
        if info.name.startswith("test_"):
            modules.append(info.name)
    total, failed = 0, 0
    failures: list[str] = []
    for name in sorted(modules):
        mod = __import__(f"tests.{name}", fromlist=["*"])
        fns = [(fn_name, fn) for fn_name, fn in vars(mod).items()
               if fn_name.startswith("test_") and callable(fn)]
        for fn_name, fn in sorted(fns):
            params = inspect.signature(fn).parameters
            if params:
                print(f"SKIP {name}.{fn_name} (needs fixtures: "
                      f"{list(params)})")
                continue
            total += 1
            try:
                fn()
            except Exception:
                failed += 1
                failures.append(f"{name}.{fn_name}\n{traceback.format_exc()}")
    print(f"\n{total - failed}/{total} tests passed")
    for f in failures:
        print("\nFAIL:", f)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
