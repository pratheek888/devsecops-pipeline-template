#!/bin/sh
# Integration test for resources/.../gitops-promote.sh against a throwaway local Git "remote".
set -eu
script="$(cd "$(dirname "$0")/.." && pwd)/resources/io/github/pratheek888/devsecops/gitops-promote.sh"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
cd "$tmp"
git init -q --bare -b main remote.git
git clone -q remote.git seed
mkdir -p seed/environments/prod
printf 'api:\n  image:\n    tag: blue # managed by CI\n' > seed/environments/prod/values.yaml
git -C seed add -A
git -C seed -c user.name=t -c user.email=t@t commit -qm init
git -C seed push -q origin main

export GITOPS_REPO="file://$tmp/remote.git" GITOPS_BRANCH=main VALUES_FILE=environments/prod/values.yaml \
       YAML_PATH=.api.image.tag APP_NAME=api TARGET_ENV=prod GIT_USER=u GIT_TOKEN=t

IMAGE_TAG=1a2b3c4d OPEN_PR=false sh "$script"
[ "$(git --git-dir=remote.git show main:environments/prod/values.yaml | yq .api.image.tag)" = "1a2b3c4d" ]
git --git-dir=remote.git show main:environments/prod/values.yaml | grep -q '# managed by CI'   # comments kept

IMAGE_TAG=1a2b3c4d OPEN_PR=false sh "$script" | grep -q 'nothing to promote'                 # idempotent

IMAGE_TAG=9f9f9f9f OPEN_PR=true sh "$script"
[ "$(git --git-dir=remote.git show main:environments/prod/values.yaml | yq .api.image.tag)" = "1a2b3c4d" ]
[ "$(git --git-dir=remote.git show promote/prod/api-9f9f9f9f:environments/prod/values.yaml | yq .api.image.tag)" = "9f9f9f9f" ]
echo "gitops-promote: all checks passed"
