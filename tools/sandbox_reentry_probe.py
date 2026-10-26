#!/usr/bin/env python3
"""Reproduce Seatbelt policy reentry without launching clients or granting acceptance."""
import ctypes
import errno
import json
import os
import platform
from pathlib import Path
import subprocess
import sys

PROFILES = {
    "unrestricted": "(version 1)(allow default)",
    "network-denied": "(version 1)(allow default)(deny network*)",
    "network-and-writes-denied": "(version 1)(allow default)(deny network*)(deny file-write*)",
}
METHODS = ("init", "parameters", "compiled")


def observe(method, profile):
    library = ctypes.CDLL("/usr/lib/libsandbox.dylib", use_errno=True)
    pointer = ctypes.c_void_p
    error_pointer = ctypes.POINTER(pointer)
    declarations = {
        "sandbox_init": ([ctypes.c_char_p, ctypes.c_uint64, error_pointer], ctypes.c_int),
        "sandbox_init_with_parameters": ([ctypes.c_char_p, ctypes.c_uint64, pointer, error_pointer], ctypes.c_int),
        "sandbox_compile_string": ([ctypes.c_char_p, pointer, error_pointer], pointer),
        "sandbox_apply": ([pointer], ctypes.c_int),
        "sandbox_check": ([ctypes.c_int, ctypes.c_char_p, ctypes.c_int], ctypes.c_int),
        "sandbox_free_error": ([pointer], None),
        "sandbox_free_profile": ([pointer], None),
    }
    for symbol, (arguments, result) in declarations.items():
        function = getattr(library, symbol)
        function.argtypes, function.restype = arguments, result
    before = library.sandbox_check(os.getpid(), None, 0)
    error = pointer()
    compiled = None
    source = profile.encode()
    try:
        ctypes.set_errno(0)
        if method == "init":
            result = library.sandbox_init(source, 0, ctypes.byref(error))
        elif method == "parameters":
            parameters = (ctypes.c_char_p * 1)(None)
            result = library.sandbox_init_with_parameters(source, 0, parameters, ctypes.byref(error))
        else:
            compiled = library.sandbox_compile_string(source, None, ctypes.byref(error))
            if not compiled:
                return {"compileFailed": True}
            ctypes.set_errno(0)
            result = library.sandbox_apply(compiled)
        observed_errno = ctypes.get_errno()
        return {
            "before": before, "after": library.sandbox_check(os.getpid(), None, 0),
            "result": result, "errno": observed_errno,
            "apiError": ctypes.string_at(error).decode("utf-8", "replace")[:512] if error.value else None,
        }
    finally:
        if error.value:
            library.sandbox_free_error(error)
        if compiled:
            library.sandbox_free_profile(compiled)


def run_case(method, outer, inner):
    arguments = [sys.executable, "-B", str(Path(__file__).resolve()), "--child", method, inner]
    if outer is not None:
        arguments = ["/usr/bin/sandbox-exec", "-p", PROFILES[outer], *arguments]
    case = {"method": method, "outer": outer, "inner": inner}
    try:
        process = subprocess.run(arguments, capture_output=True, text=True, timeout=10)
        case["processExit"] = process.returncode
        if process.returncode != 0:
            case["executionError"] = process.stderr[-512:]
            case["matchesExpectedReentryBehavior"] = False
            return case
        observation = json.loads(process.stdout)
        case["observation"] = observation
        same_or_initial = outer is None or outer == inner
        case["matchesExpectedReentryBehavior"] = (
            observation.get("before") == (0 if outer is None else 1)
            and observation.get("after") == 1
            and (observation.get("result") == 0 if same_or_initial else
                 observation.get("result") == -1 and observation.get("errno") == errno.EPERM)
        )
    except (OSError, subprocess.TimeoutExpired, ValueError) as error:
        case.update(executionError=type(error).__name__, matchesExpectedReentryBehavior=False)
    return case


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "--child":
        if sys.argv[2] not in METHODS or sys.argv[3] not in PROFILES:
            return 2
        print(json.dumps(observe(sys.argv[2], PROFILES[sys.argv[3]])))
        return 0
    if len(sys.argv) != 1 or sys.platform != "darwin":
        print("This diagnostic requires macOS and accepts no arguments.", file=sys.stderr)
        return 2
    cases = [run_case(method, outer, inner) for method in METHODS
             for outer in (None, *PROFILES) for inner in PROFILES]
    reproduced = all(case["matchesExpectedReentryBehavior"] for case in cases)
    print(json.dumps({
        "os": platform.platform(), "profiles": PROFILES, "cases": cases,
        "status": "different-policy-reentry-rejected" if reproduced else "inconclusive",
        "productionLaunchAllowed": False,
        "scope": "Independent sandbox API probes only; no Claude, network traffic or acceptance writes",
    }, indent=2))
    return 0 if reproduced else 1


if __name__ == "__main__":
    sys.exit(main())
