#!/bin/bash

set -eo pipefail

function add_plugin() {
	local plugin=$(basename $1)
	local br_deploy="$1/deploy/buildroot"

	if [ ! -e "$br_deploy" ]; then
		echo "Buildroot deploy path not found: $br_deploy"
		exit 1
	fi

	if [ -h "$self/package/$plugin" ]; then
		echo "Plugin already installed: $plugin"
		return
	fi

	echo "Adding plugin: $plugin"
	ln -vs "$br_deploy" "$self/package/$plugin"
	echo -e "source \"\$BR2_EXTERNAL_netifyd_PATH/package/$plugin/Config.in\"" >> "$self/Config.in"
}

if [ $# -eq 0 ]; then
	echo "$0 <plugin path> [<plugin_path>]..."
	exit 0
fi

self="$(dirname $(realpath "$0"))"

while [ $# -gt 0 ]; do
	plugin="$(realpath "$1")"
	if [ ! -e "$plugin" ]; then
		echo "$0: $plugin: not found."
		exit 1
	fi

	add_plugin $plugin
	shift
done

exit 0
