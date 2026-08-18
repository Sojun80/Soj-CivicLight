#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ssh_target=${SOJ_SSH_TARGET:-sojun@sojllm.local}
remote_dir=${SOJ_SHARE_DIR:-/home/sojun/lan-share}
remote_dir=${remote_dir%/}

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

    echo "Uploading $binary to $ssh_target:$remote_dir/$binary"
    scp -p "$path" "$ssh_target:$remote_dir/$binary"
done

echo "Upload complete."
