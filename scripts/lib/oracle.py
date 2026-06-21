from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import re

# Sanitizer keywords (strong crash-like signals only).
# Avoid matching benign strings like "WARNING: AddressSanitizer failed to allocate ...".
ASAN_RE = re.compile(
    r"ERROR:\s*AddressSanitizer|"
    r"AddressSanitizer:|"
    r"SUMMARY:\s*AddressSanitizer|"
    r"UndefinedBehaviorSanitizer:|"
    r"runtime error:",
    re.IGNORECASE
)

# Generic crash keywords
CRASH_RE = re.compile(
    r"segmentation fault|"
    r"dumped core|"
    r"core dumped|"
    r"SIGSEGV|"
    r"SIGABRT|"
    r"heap-buffer-overflow|"
    r"stack-buffer-overflow|"
    r"use-after-free|"
    r"double-free|"
    r"SUMMARY: AddressSanitizer|"
    r"SUMMARY: UndefinedBehaviorSanitizer|"
    r"DIFFERENT POINTERS returned|"
    r"Dictionary corruption confirmed",
    re.IGNORECASE
)

# Crash exit codes (SIGSEGV=11, SIGABRT=6, with 128 offset)
CRASH_EXIT_CODES = {139, 134, -11, -6, 11, 6}

@dataclass(frozen=True)
class RunResult:
    exit_code: int
    stdout: str
    stderr: str

def looks_like_sanitizer_crash(res: RunResult) -> bool:
    """
    Detect if result shows any crash indication:
    - Sanitizer output (ASan/UBSan)
    - Crash keywords (segfault, core dump)
    - Crash exit codes (139=SIGSEGV, 134=SIGABRT)
    """
    combined = res.stdout + "\n" + res.stderr
    
    # Check for sanitizer or crash keywords
    if ASAN_RE.search(combined) or CRASH_RE.search(combined):
        return True
    
    # Check exit code
    if res.exit_code in CRASH_EXIT_CODES:
        return True
    
    return False

@dataclass(frozen=True)
class Verdict:
    vuln_crashes: bool
    fixed_crashes: bool

    @property
    def success(self) -> bool:
        return self.vuln_crashes and (not self.fixed_crashes)

def verdict(vuln: RunResult, fixed: RunResult) -> Verdict:
    return Verdict(
        vuln_crashes=looks_like_sanitizer_crash(vuln),
        fixed_crashes=looks_like_sanitizer_crash(fixed),
    )
