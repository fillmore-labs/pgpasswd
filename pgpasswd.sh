#!/bin/sh -eu

if [ $# -ne 2 ]; then
    echo "Usage: $0 <username> <password>"
    exit 1
fi

PASSOWRD=$(go run . "$2")

cat << _SQL
CREATE ROLE "$1" WITH
  LOGIN
  PASSWORD '$PASSOWRD';
_SQL
