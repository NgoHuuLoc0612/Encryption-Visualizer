#!/usr/bin/env python3
"""
build.py — Compile crypto_engine C++ extension via pybind11
Cross-platform: Windows (MSVC cl.exe / MinGW g++), Linux, macOS

Usage:
    python build.py              # auto-detect compiler, release build
    python build.py --debug      # debug symbols
    python build.py --clean      # clean build artifacts
    python build.py --compiler mingw    # force MinGW g++ on Windows
    python build.py --compiler msvc     # force MSVC cl.exe on Windows
"""
import subprocess, sys, os, shutil, sysconfig, shlex
from pathlib import Path

ROOT  = Path(__file__).parent.resolve()
BUILD = ROOT / "build"
IS_WIN   = sys.platform == "win32"
IS_MAC   = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")


# ── Helpers ────────────────────────────────────────────────────────────────────

def run(cmd: list, shell=False):
    display = " ".join(f'"{x}"' if " " in str(x) else str(x) for x in cmd)
    print(f"\n$ {display}\n")
    r = subprocess.run(cmd, shell=shell)
    if r.returncode != 0:
        print(f"\n[ERROR] Command exited with code {r.returncode}")
        sys.exit(r.returncode)


def clean():
    for d in [BUILD, ROOT / "__pycache__"]:
        if d.exists():
            shutil.rmtree(d)
            print(f"Removed {d}")
    for ext in ["*.pyd", "*.so", "*.dll"]:
        for f in ROOT.glob(ext):
            if f.name.startswith("crypto_engine"):
                f.unlink()
                print(f"Removed {f}")


def find_compiler() -> str:
    """Detect best available compiler on PATH."""
    candidates = []
    if IS_WIN:
        candidates = ["cl", "g++", "c++", "clang++"]
    elif IS_MAC:
        candidates = ["clang++", "g++", "c++"]
    else:
        candidates = ["g++", "c++", "clang++"]

    for name in candidates:
        if shutil.which(name):
            return name
    return None


def detect_msvc_env() -> dict | None:
    """
    Try to find and activate a MSVC environment via vswhere + vcvarsall.
    Returns extra env dict or None.
    """
    vswhere = Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)")) / \
              "Microsoft Visual Studio/Installer/vswhere.exe"
    if not vswhere.exists():
        return None
    result = subprocess.run(
        [str(vswhere), "-latest", "-property", "installationPath"],
        capture_output=True, text=True
    )
    if result.returncode != 0 or not result.stdout.strip():
        return None
    vs_path = Path(result.stdout.strip())
    vcvars = vs_path / "VC/Auxiliary/Build/vcvars64.bat"
    if not vcvars.exists():
        vcvars = vs_path / "VC/Auxiliary/Build/vcvarsamd64.bat"
    if not vcvars.exists():
        return None
    # Dump env after vcvars
    dump = subprocess.run(
        f'"{vcvars}" && set', shell=True, capture_output=True, text=True
    )
    env = {}
    for line in dump.stdout.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            env[k.strip()] = v.strip()
    return env


# ── MSVC build ─────────────────────────────────────────────────────────────────

def build_msvc(pb11_inc, py_inc, py_libs_dir, py_lib_name, output, debug):
    """Build with MSVC cl.exe"""
    print("[MSVC] Attempting MSVC build...")
    msvc_env = detect_msvc_env()
    if msvc_env is None:
        print("[WARN] Could not auto-activate MSVC env. Ensure you run from a Developer Command Prompt.")
        msvc_env = os.environ.copy()

    src = [str(ROOT / "crypto_core.cpp"), str(ROOT / "bindings.cpp")]
    obj_dir = BUILD / "obj"
    obj_dir.mkdir(exist_ok=True)

    opt = ["/Od", "/Zi"] if debug else ["/O2"]
    cl_flags = [
        "cl", "/nologo", "/EHsc", "/MD",
        f"/std:c++17",
        *opt,
        f"/I{pb11_inc}", f"/I{py_inc}", f"/I{ROOT}",
        "/LD",                              # build DLL
        *src,
        f"/Fe{output}",                     # output .pyd
        "/link",
        f"/LIBPATH:{py_libs_dir}",
        f"{py_lib_name}.lib",
        "/EXPORT:PyInit_crypto_engine",
    ]
    r = subprocess.run(cl_flags, env=msvc_env, cwd=str(BUILD))
    if r.returncode != 0:
        print("[ERROR] MSVC compile failed.")
        sys.exit(r.returncode)


# ── GCC / Clang build ──────────────────────────────────────────────────────────

def build_gcc(compiler, pb11_inc, py_inc, output, debug):
    """Build with g++ / clang++ / c++"""
    print(f"[GCC/Clang] Using compiler: {compiler}")

    opt = ["-O0", "-g"] if debug else ["-O3"]
    flags = [
        compiler,
        f"-std=c++17",
        *opt,
        "-fPIC" if not IS_WIN else "",
        "-Wall",
        "-fvisibility=hidden",
        f"-I{pb11_inc}",
        f"-I{py_inc}",
        f"-I{ROOT}",
    ]
    flags = [f for f in flags if f]  # drop empty strings

    sources = [str(ROOT / "crypto_core.cpp"), str(ROOT / "bindings.cpp")]

    if IS_WIN:
        # MinGW on Windows
        py_base   = Path(sysconfig.get_config_var("BINDIR") or sys.prefix)
        py_libdir = py_base / "libs"
        py_ver    = f"python{sys.version_info.major}{sys.version_info.minor}"
        link = [
            "-shared",
            f"-L{py_libdir}",
            f"-l{py_ver}",
            "-static-libgcc", "-static-libstdc++",
            "-Wl,--enable-auto-image-base",
        ]
    elif IS_MAC:
        link = ["-shared", "-undefined", "dynamic_lookup"]
    else:
        link = ["-shared"]

    cmd = flags + sources + link + ["-o", str(output)]
    run(cmd)


# ── Main build ─────────────────────────────────────────────────────────────────

def build(debug=False, force_compiler=None):
    BUILD.mkdir(exist_ok=True)

    # pybind11
    try:
        import pybind11
        pb11_inc = pybind11.get_include()
    except ImportError:
        print("[ERROR] pybind11 not found. Run:  pip install pybind11")
        sys.exit(1)

    py_inc     = sysconfig.get_path("include")
    ext_suffix = sysconfig.get_config_var("EXT_SUFFIX") or ".pyd"
    output     = BUILD / f"crypto_engine{ext_suffix}"

    print(f"{'='*60}")
    print(f"  Platform  : {sys.platform}")
    print(f"  Python    : {sys.version.split()[0]}")
    print(f"  pybind11  : {pb11_inc}")
    print(f"  Output    : {output}")
    print(f"  Debug     : {debug}")
    print(f"{'='*60}")

    compiler = force_compiler or find_compiler()

    # Windows — try MSVC first unless forced to mingw
    if IS_WIN and (force_compiler == "msvc" or (compiler == "cl" and force_compiler != "mingw")):
        py_cfg     = sysconfig.get_config_var
        py_libs    = Path(sys.prefix) / "libs"
        py_libname = f"python{sys.version_info.major}{sys.version_info.minor}"
        build_msvc(pb11_inc, py_inc, py_libs, py_libname, output, debug)
    else:
        if compiler is None:
            print("[ERROR] No C++ compiler found on PATH.")
            print("  Windows options:")
            print("    1) Install Visual Studio (Community) with C++ workload")
            print("    2) Install MinGW-w64  →  https://winlibs.com/")
            print("    3) Use: winget install mingw")
            sys.exit(1)
        build_gcc(compiler, pb11_inc, py_inc, output, debug)

    if not output.exists():
        print(f"[ERROR] Expected output not found: {output}")
        sys.exit(1)

    # Copy to project root so 'import crypto_engine' works from ROOT
    dest = ROOT / output.name
    shutil.copy(output, dest)
    print(f"\n{'='*60}")
    print(f"  ✓ Built  : {output}")
    print(f"  ✓ Copied : {dest}")
    print(f"  → Run    : python server.py")
    print(f"{'='*60}\n")


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    args = sys.argv[1:]
    if "--clean" in args:
        clean()
        if "--clean" == args[-1]:   # only clean, no build
            sys.exit(0)

    force = None
    if "--compiler" in args:
        idx = args.index("--compiler")
        if idx + 1 < len(args):
            force = args[idx + 1].lower()

    build(debug="--debug" in args, force_compiler=force)
