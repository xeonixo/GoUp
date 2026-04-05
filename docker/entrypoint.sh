#!/bin/sh
set -eu

mode="${GOUP_MODE:-server}"

case "$mode" in
	server)
		exec /usr/local/bin/goup "$@"
		;;
	remote-node)
		exec /usr/local/bin/remote-node "$@"
		;;
	*)
		echo "unknown GOUP_MODE: $mode" >&2
		exit 1
		;;
	esac