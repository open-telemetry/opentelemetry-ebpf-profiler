#!/bin/bash -u
#
# Requires license-detector from https://github.com/go-enry/go-license-detector/releases/tag/v4.3.0 
# to be installed in the current directory.

function cleanup {
  rm  -rf tmp
}
trap cleanup EXIT

check_manually=""
exceptions="github.com/opencontainers/go-digest" # Apache2.0 but reported as CC-BY-SA-4.0

dirs=$(grep -E '^[[:blank:]]+.+\..+/.+' ../go.mod | awk '{print $1}')

for dir_versioned in $dirs; do
  found="no"
  for except in $exceptions; do
    if [ $except == "$dir_versioned" ]; then found="yes"; break; fi
  done
  if [ "$found" == "yes" ]; then continue; fi

  echo $dir_versioned":"
  dir=$dir_versioned

  # versioned paths can not be used by the license-detector
  if [[ $dir =~ /v[0-9]$ ]]; then
    dir=${dir%/*}
  fi

  if [ -n "${dir%%github.com/*}" ]; then
    repo=$(curl -Ls "https://$dir?go-get=1" | xml2 2>/dev/null | grep -E '/meta/@content=.+\..+ git ' | awk '{print $3}')
  else
    # e.g. github.com/moby/sys/user -> github.com/moby/sys
    repo_dir=$(echo $dir|cut -d'/' -f1-3)
    repo="https://$repo_dir"
  fi
  echo "  $repo"

  if [ -z "${repo%%https://github.com/*}" ]; then
    json=$(curl -sL "https://api.github.com/repos/$(echo $repo | cut -d'/' -f4-)" -H 'Accept: application/vnd.github.preview')
    read -r stars forks license created < \
         <(jq -r '"\(.stargazers_count) \(.forks) \(.license.spdx_id) \(.created_at)"' <<< "$json")
    echo "  Github created=$created, stars=$stars, forks=$forks, license=$license"

    # Avoid the heavy-weight license-detector if possible
    if [ "$license" == "Apache-2.0" ]; then
      echo "  Apache-2.0 --> no copy required"
      continue
    fi
  fi

  if [ "$license" == "Apache-2.0" ]; then
    echo "  Apache-2.0 --> no copy required"
    continue
  fi

  json=$(./license-detector $repo -f json)
  read -r license file < \
       <(jq -r '"\(.[0].matches[0].license) \(.[0].matches[0].file)"' <<< "$json")

  if [ "$license" == "null" ]; then
    echo "  No license found, check manually"
    check_manually="$check_manually $repo"
    continue
  fi

  if [ "$file" == "null" ]; then
    echo "  No file found, check manually"
    check_manually="$check_manually $repo"
    continue
   fi

  echo "  license=$license, file=$file"
  rm -rf tmp
  git clone -q --depth=1 "$repo" tmp
  mkdir -p "$dir_versioned"
  cp "tmp/$file" "$dir_versioned/"
  rm -rf tmp
done

if [ "$check_manually" == "" ]; then exit 0; fi

echo
echo "Please check these dependencies manually:"
echo $check_manually | tr ' ' '\n'
