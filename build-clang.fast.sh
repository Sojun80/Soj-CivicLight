#!/bin/sh
set -e
exec "$(dirname "$0")/build-clang-fast.sh" "$@"
