#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
share_url=${SOJ_SHARE_URL:-http://192.168.1.25:8088}
share_url=${share_url%/}

if [ "$#" -gt 0 ]; then
    binaries="$*"
else
    binaries="soj-civiclight-znver2 soj-civiclight-znver4"
fi

for binary in $binaries; do
    path=$repo_dir/$binary
    if [ ! -f "$path" ]; then
        echo "Missing binary: $path" >&2
        exit 1
    fi

    echo "Uploading $binary to $share_url/$binary"
    curl --fail --show-error --retry 2 \
        --upload-file "$path" \
        "$share_url/$binary"
done

echo "Upload complete."
