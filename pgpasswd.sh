#!/bin/sh -eu

if [ $# -ne 2 ]; then
    echo "Usage: $0 <username> <password>"
    exit 1
fi

go run . "$1" "$2" "x"
