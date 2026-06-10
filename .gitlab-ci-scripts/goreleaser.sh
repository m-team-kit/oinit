#!/bin/bash

# Run goreleaser directly against the CI checkout.
#
# Previously this wrapped goreleaser in a nested "docker run -v $PWD:...". That
# bind mount is resolved by the Docker daemon (dind service / host socket),
# whose filesystem does not contain the GitLab checkout at $CI_PROJECT_DIR, so
# goreleaser started in an empty directory and failed intermittently with
# "not a git repository" / "could not find a configuration file".
#
# The package stage needs no Docker daemon (the dockers section in
# .goreleaser.yaml is disabled and we pass --skip docker), so goreleaser is
# run natively in the goreleaser image instead.

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
echo -e "--------------- /files -----------------"

echo -e "--------------- version -----------------"
goreleaser --version

echo -e "--------------- running -----------------"
echo "    goreleaser release --skip publish --skip docker --verbose ${GORELEASER_OPTIONS}"

# run goreleaser to build packages
goreleaser release --skip publish --skip docker --verbose ${GORELEASER_OPTIONS}
# do not add commands here, script exits with status of last command
