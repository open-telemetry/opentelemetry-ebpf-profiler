#!/usr/bin/env bash

# Script to append legal information for non Go dependencies.

set -eu
set -o pipefail

nonGoDependencies="${1:-non-go-dependencies.json}"
depsFile="${2:-deps.csv}"

for item in $(jq -c . "${nonGoDependencies}"); do
    dependency=$(jq -r '.Dependency' <<< "$item")
    version=$(jq -r '.Version' <<< "$item")
    licence=$(jq -r '.Licence' <<< "$item")
    url=$(jq -r '.URL' <<< "$item")
    {
    echo "$dependency,$url,$version,,$licence"
    } >> "${depsFile}"
done
