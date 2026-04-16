#!/bin/bash

BASEDIR=/go/src/github.com/lbrocke/oinit
# check version of goreleaser
docker images | grep goreleaser
# update goreleaser
docker pull goreleaser/goreleaser

GORELEASER_OPTIONS=""
[[ "${CI_COMMIT_BRANCH}" != "${CI_DEFAULT_BRANCH}" ]] && {
    [[ "${CI_COMMIT_BRANCH}" != "${PREREL_BRANCH_NAME}" ]] && {
        # we're on devel
        GORELEASER_OPTIONS=""
    }
}
echo "PWD: ${PWD}"
echo "git status:"
git status
echo -e "---------------- files -----------------"
ls -la
echo -e "---------------- files-in-docker -----------------"
docker run --rm --privileged \
  -v "$PWD":"$BASEDIR" \
  -w "$BASEDIR" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  ls -la
echo -e "--------------- /files -----------------"

docker run --rm --privileged \
  -v "$PWD":"$BASEDIR" \
  -w "$BASEDIR" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  goreleaser/goreleaser --version

echo "Running:"
echo "    goreleaser/goreleaser release --skip publish --skip docker --verbose  ${GORELEASER_OPTIONS}"

# run goreleaser to build packages
docker run --rm --privileged \
  -v "$PWD":"$BASEDIR" \
  -w "$BASEDIR" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  goreleaser/goreleaser release --skip publish --skip docker --verbose \
    ${GORELEASER_OPTIONS}
# do not add commands here, script exists with status of last command
