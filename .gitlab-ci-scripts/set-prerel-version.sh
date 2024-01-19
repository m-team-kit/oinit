#!/bin/sh

DEVSTRING="pr"
VERSION_FILE=VERSION

while [ $# -gt 0 ]; do
  case $1 in
    --devstring)
      DEVSTRING="$2"
      shift # past argument
      shift # past value
      ;;
    --version_file)
      VERSION_FILE="$2"
      shift # past argument
      shift # past value
      ;;
    --*|-*)
      echo "Unknown option $1"
      exit 1
      ;;
  esac
done

git config user.email || {
    echo "Setting up git in CI"
    git config --global --add safe.directory "$PWD"
    git config user.email "ci@repo.data.kit.edu"
    git config user.name "cicd"
}

# Get master branch name:
#   use origin if exists
#   else use last found remote
MASTER_BRANCH=""
get_master_branch_of_mteam() {
    git remote -vv | awk -F[\\t@:] '{ print $1 " " $3 }' | while read REMOTE HOST; do 
        # echo " $HOST -- $REMOTE"
        MASTER=$(git remote show "$REMOTE"  2>/dev/null \
            | sed -n '/HEAD branch/s/.*: //p')
        MASTER_BRANCH="refs/remotes/${REMOTE}/${MASTER}"
        [ "x${HOST}" == "xcodebase.helmholtz.cloud" ] && {
            echo "${MASTER_BRANCH}"
            break
        }
        [ "x${HOST}" == "xgit.scc.kit.edu" ] && {
            echo "${MASTER_BRANCH}"
            break
        }
        [ "x${REMOTE}" == "xorigin" ] && {
            echo "${MASTER_BRANCH}"
            break
        }
    done
}

MASTER_BRANCH=$(get_master_branch_of_mteam)
PREREL=$(git rev-list --count HEAD ^"$MASTER_BRANCH")

# use version file:
VERSION=$(cat "$VERSION_FILE")
PR_VERSION="${VERSION}-${DEVSTRING}${PREREL}"
echo "$PR_VERSION" > "$VERSION_FILE"
echo "$PR_VERSION"

echo "$PR_VERSION" > "$VERSION_FILE"
git add "$VERSION_FILE"
git commit -m "dummy prerel version"
git tag "v${PR_VERSION}"
