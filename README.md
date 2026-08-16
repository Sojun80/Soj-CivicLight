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

### Windows (64-bit MinGW)

Use `build-mingw64.sh` from a MinGW/MSYS2 shell, or from Linux with a
cross-toolchain. Set `SOJ_MINGW_PREFIX` to the target dependency prefix; it
must contain MinGW-built curl, OpenSSL, GMP, and zlib headers and libraries:

```sh
SOJ_MINGW_PREFIX=/mingw64 ./build-mingw64.sh
```

The script checks the target headers and import/static libraries before
configuring, then writes `soj-civiclight-windows-x86_64.exe`. Dependencies
must be built for the same MinGW target; Linux libraries are not compatible.
The resulting executable uses the MinGW POSIX-thread runtime, so ship the
matching `libwinpthread-1.dll` beside it (or provide it through the Windows
runtime `PATH`).

#### Cross-building the dependency prefix

The prefix must contain target Windows libraries, not the Linux development
packages. The following is the complete Linux cross-build recipe used for the
portable build below. It keeps all third-party sources and output outside the
repository:

```sh
DEPS=/tmp/soj-mingw64-deps
PREFIX=$DEPS/stage
ZLIB_SYSROOT=/usr/x86_64-w64-mingw32
mkdir -p "$DEPS/src" "$DEPS/build" "$PREFIX"

curl -L --fail -o "$DEPS/src/gmp-6.3.0.tar.xz" \
  https://ftp.gnu.org/gnu/gmp/gmp-6.3.0.tar.xz
curl -L --fail -o "$DEPS/src/openssl-3.0.16.tar.gz" \
  https://www.openssl.org/source/openssl-3.0.16.tar.gz
curl -L --fail -o "$DEPS/src/curl-8.10.1.tar.xz" \
  https://curl.se/download/curl-8.10.1.tar.xz
tar -xf "$DEPS/src/gmp-6.3.0.tar.xz" -C "$DEPS/src"
tar -xf "$DEPS/src/openssl-3.0.16.tar.gz" -C "$DEPS/src"
tar -xf "$DEPS/src/curl-8.10.1.tar.xz" -C "$DEPS/src"

mkdir "$DEPS/build/gmp"
cd "$DEPS/build/gmp"
CC_FOR_BUILD=gcc CPP_FOR_BUILD='gcc -E' \
  "$DEPS/src/gmp-6.3.0/configure" \
  --host=x86_64-w64-mingw32 --build=x86_64-pc-linux-gnu \
  --prefix="$PREFIX" --enable-static --disable-shared --disable-assembly \
  CFLAGS='-O2'
make -j2 && make install

mkdir "$DEPS/build/openssl"
cd "$DEPS/build/openssl"
"$DEPS/src/openssl-3.0.16/Configure" mingw64 no-shared no-tests no-asm \
  --cross-compile-prefix=x86_64-w64-mingw32- \
  --prefix="$PREFIX" --openssldir="$PREFIX/ssl"
make -j2 && make install_sw
mkdir -p "$PREFIX/lib"
cp "$PREFIX/lib64/libssl.a" "$PREFIX/lib64/libcrypto.a" "$PREFIX/lib/"

# Reuse the target zlib already supplied by the MinGW toolchain.
cp "$ZLIB_SYSROOT/include/zlib.h" "$ZLIB_SYSROOT/include/zconf.h" "$PREFIX/include/"
cp "$ZLIB_SYSROOT/lib/libz.a" "$PREFIX/lib/"

mkdir "$DEPS/build/curl"
cd "$DEPS/build/curl"
CPPFLAGS="-I$PREFIX/include -I$ZLIB_SYSROOT/include" \
LDFLAGS="-L$PREFIX/lib -L$ZLIB_SYSROOT/lib" \
LIBS='-lws2_32 -lcrypt32 -lgdi32' \
  "$DEPS/src/curl-8.10.1/configure" \
  --host=x86_64-w64-mingw32 --build=x86_64-pc-linux-gnu \
  --prefix="$PREFIX" --disable-shared --enable-static \
  --with-openssl="$PREFIX" --with-zlib="$ZLIB_SYSROOT" \
  --without-nghttp2 --without-brotli --without-zstd --without-libpsl \
  --disable-ldap --disable-rtsp --disable-dict --disable-telnet \
  --disable-tftp --disable-pop3 --disable-imap --disable-smb \
  --disable-smtp --disable-gopher --disable-mqtt --disable-manual \
  --disable-docs --without-libidn2 --without-libssh2 \
  --without-gnutls --without-mbedtls --without-wolfssl
make -j2 && make install

# Keep only the static zlib archive in PREFIX/lib; otherwise the linker may
# select libz.dll.a and add a zlib1.dll runtime dependency.
mv "$PREFIX/lib/libz.dll.a" "$PREFIX/lib/libz.dll.a.import" 2>/dev/null || true
```

Then build SOJ itself:

```sh
cd /path/to/soj-civiclight
SOJ_MINGW_PREFIX="$PREFIX" ./build-mingw64.sh
```

The script verifies `curl/curl.h`, `openssl/ssl.h`, `gmp.h`, and the five
static libraries before configuring. It also defines `CURL_STATICLIB`, adds
the Windows system libraries, disables unsupported POSIX crash/priority paths,
and performs a clean rebuild so stale objects cannot mix flags. The output is
`soj-civiclight-windows-x86_64.exe`.

For a cross-built test bundle, copy the matching MinGW thread runtime next to
the executable (the exact location depends on the toolchain):

```sh
cp /usr/x86_64-w64-mingw32/lib/libwinpthread-1.dll .
```

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
