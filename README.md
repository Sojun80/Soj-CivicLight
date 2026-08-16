# SOJ CivicLight Miner

This repository contains the focused SOJ runtime for CivicNet's `civiclight`
algorithm and its retained yespower optimizations.

## Build

The primary build uses the Clang-fast build script:

```sh
./build-clang-fast.sh
```

It targets AMD Zen 2 or newer with AVX2 and SHA-NI, builds the `soj` miner, and
runs a CivicLight v2 consensus-vector test before writing a timestamped local
backup. The build and test path is offline.

The binary contains separate yespower implementations for Rome/AVX2 and
AVX-512F+VL CPUs. Algorithm registration selects the implementation once and
the mining loop calls the cached function pointer directly, with no per-hash
feature branch. The active path is shown on the `[SYSTEM]` line.

Normal startup also displays a terminal-safe ASCII Mudflap Girl banner. It is
omitted by quiet and hardened-silent builds.

## Benchmark

```sh
./soj -a civiclight --benchmark 15 -t 1
./soj -a civiclight --benchmark 15 -t 8
```

The benchmark forces a post-fork timestamp so it measures memory-hard
CivicLight v2 rather than the retired v1 algorithm.

The focused Salsa-initialization benchmark compares the serial and paired
calculations in one process and verifies their output after every chunk:

```sh
./bench-civiclight-salsa.sh
```

It is also entirely offline. Adjust the run length with
`CIVIC_SALSA_BENCH_CHUNKS` and `CIVIC_SALSA_BENCH_ITERATIONS`.

## Mine

```sh
CIVIC_POOL=stratum+tcp://pool.example:port \
CIVIC_USER=YOUR_ADDRESS.worker \
CIVIC_PASS=x \
  ./mine-civiclight.sh
```

The launcher starts one miner process with eight threads by default. Pool and
worker credentials are intentionally supplied through environment variables.

Override any value without editing the script, for example:

```sh
CIVIC_THREADS=6 CIVIC_POOL=stratum+tcp://pool.example:port \
  CIVIC_USER=YOUR_ADDRESS.worker ./mine-civiclight.sh
```

### Ryzen 9 7950X3D

Use the preserved dual-CCD launcher on the 7950X3D:

```sh
./mine-civiclight-7950x3d.sh
```

It starts two `numactl`-pinned processes:

- CCD0: CPUs `0-7`, 8 threads
- CCD1: CPUs `8-15`, 8 threads

Install `numactl` once if needed:

```sh
sudo apt-get install numactl
```

Override its values without editing the script, for example:

```sh
CIVIC_CCD_THREADS=6 CIVIC_POOL=stratum+tcp://pool.example:port \
  CIVIC_USER=YOUR_ADDRESS.worker ./mine-civiclight-7950x3d.sh
```

Override the CPU lists if firmware or the kernel enumerates the CCDs
differently:

```sh
for f in /sys/devices/system/cpu/cpu*/cache/index3/shared_cpu_list; do
  cat "$f"
done | sort -u

CIVIC_CCD0_CPUS=0-7 CIVIC_CCD1_CPUS=8-15 ./mine-civiclight-7950x3d.sh
```

The defaults use one hardware thread per physical core. To test SMT, include
the sibling threads and raise the per-CCD thread count:

```sh
CIVIC_CCD0_CPUS=0-7,16-23 CIVIC_CCD1_CPUS=8-15,24-31 \
  CIVIC_CCD_THREADS=16 ./mine-civiclight-7950x3d.sh
```

After setting the pool and worker variables, pass normal miner options after
the script name. A bounded smoke run is:

```sh
CIVIC_POOL=stratum+tcp://pool.example:port CIVIC_USER=YOUR_ADDRESS.worker \
  ./mine-civiclight.sh --time-limit=30
```
