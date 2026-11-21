#!/bin/sh
# Bump an image tag in a GitOps repository (e.g. Argo CD environments/<env>/values.yaml).
# Inputs (env): GITOPS_REPO, GITOPS_BRANCH, VALUES_FILE, YAML_PATH, IMAGE_TAG, APP_NAME, TARGET_ENV,
#               GIT_USER, GIT_TOKEN, OPEN_PR (true = push a promote/* branch for review instead of main)
set -eu

workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT

# Credentials go through a helper, so the token never shows up in the URL, process list or logs.
# Single quotes on purpose: git's helper expands the variables at auth time, not this shell.
# shellcheck disable=SC2016
helper='!f() { echo "username=${GIT_USER}"; echo "password=${GIT_TOKEN}"; }; f'

git -c credential.helper="$helper" \
    clone --quiet --depth 1 --branch "$GITOPS_BRANCH" "$GITOPS_REPO" "$workdir"
cd "$workdir"

current=$(yq "$YAML_PATH" "$VALUES_FILE")
if [ "$current" = "$IMAGE_TAG" ]; then
  echo "$VALUES_FILE already at $IMAGE_TAG, nothing to promote"
  exit 0
fi

yq -i "$YAML_PATH = \"$IMAGE_TAG\"" "$VALUES_FILE"
git config user.name "jenkins-devsecops"
git config user.email "jenkins@noreply.local"
git add "$VALUES_FILE"
git commit --quiet -m "deploy(${TARGET_ENV}): ${APP_NAME} ${current} -> ${IMAGE_TAG}"

push() {
  git -c credential.helper="$helper" push --quiet origin "$1"
}

if [ "${OPEN_PR:-false}" = "true" ]; then
  branch="promote/${TARGET_ENV}/${APP_NAME}-${IMAGE_TAG}"
  git checkout --quiet -b "$branch"
  push "$branch"
  echo "pushed $branch: open a pull request to promote ${APP_NAME} ${IMAGE_TAG} to ${TARGET_ENV}"
else
  push "HEAD:${GITOPS_BRANCH}"
  echo "promoted ${APP_NAME} to ${IMAGE_TAG} in ${TARGET_ENV} (${VALUES_FILE})"
fi
