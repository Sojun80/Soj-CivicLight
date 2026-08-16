#!/bin/sh
set -eu

# Build a 64-bit Windows executable from a MinGW/MSYS2 shell or a Linux
# cross-toolchain. The dependency prefix must contain curl, OpenSSL, GMP,
# and zlib built for the same MinGW target.

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
HOST=${SOJ_MINGW_HOST:-x86_64-w64-mingw32}
PREFIX=${SOJ_MINGW_PREFIX:-/mingw64}
CC=${CC:-${HOST}-gcc}
CXX=${CXX:-${HOST}-g++}
WINDRES=${WINDRES:-${HOST}-windres}

fail() {
    echo "build-mingw64: $*" >&2
    exit 1
}

command -v "$CC" >/dev/null 2>&1 || fail "compiler not found: $CC"
command -v "$CXX" >/dev/null 2>&1 || fail "compiler not found: $CXX"
command -v "$WINDRES" >/dev/null 2>&1 || fail "resource compiler not found: $WINDRES"
[ -d "$PREFIX/include" ] || fail "dependency prefix does not exist: $PREFIX"
[ -d "$PREFIX/lib" ] || fail "dependency library directory does not exist: $PREFIX/lib"

for header in curl/curl.h openssl/ssl.h gmp.h; do
    [ -f "$PREFIX/include/$header" ] || fail "missing $PREFIX/include/$header (install target Windows dependencies first)"
done

has_library() {
    name=$1
    for candidate in "$PREFIX/lib/$name.a" "$PREFIX/lib/$name.dll.a" "$PREFIX/lib/$name.lib"; do
        [ -f "$candidate" ] && return 0
    done
    return 1
}

for library in libcurl libssl libcrypto libgmp libz; do
    has_library "$library" || fail "missing $library in $PREFIX/lib"
done

cd "$ROOT_DIR"

if git_hash=$(git rev-parse --short --verify HEAD 2>/dev/null); then :; else git_hash=unknown; fi
if git_branch=$(git symbolic-ref --short -q HEAD 2>/dev/null); then :; else git_branch=unknown; fi
build_date=$(date -u '+%Y-%m-%d %H:%M:%S UTC')
build_version=${SOJ_BUILD_VERSION:-windows-mingw64}

sed \
    -e "s/@BUILD_VERSION@/$build_version/g" \
    -e "s/@BUILD_GIT_HASH@/$git_hash/g" \
    -e "s/@BUILD_GIT_BRANCH@/$git_branch/g" \
    -e "s/@BUILD_DATE@/$build_date/g" \
    -e 's/@BUILD_TYPE@/mingw64/g' \
    version.h.in > version.h

export CC CXX WINDRES
export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
export CFLAGS="${CFLAGS:--O2 -mavx2 -msha}"
export CXXFLAGS="${CXXFLAGS:-$CFLAGS}"
export CPPFLAGS="${CPPFLAGS:--I$PREFIX/include}"
export LDFLAGS="${LDFLAGS:--L$PREFIX/lib}"

./autogen.sh
./configure \
    --host="$HOST" \
    --build="${SOJ_BUILD_TRIPLE:-x86_64-pc-linux-gnu}" \
    --with-curl="$PREFIX" \
    --disable-assembly
make -j"${JOBS:-2}"

output=${SOJ_WINDOWS_OUTPUT:-soj-civiclight-windows-x86_64.exe}
cp -f soj.exe "$output"
echo "Windows build complete: $ROOT_DIR/$output"
