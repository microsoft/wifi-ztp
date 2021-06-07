#!/bin/bash

set -euf -o pipefail

TEMPDIR=
DEBUG=
FEATURE=ztpd
REDIRECT=/dev/null
GIT_REPO_DEFAULT="git@github.com:microsoft/wifi-ztp.git"
RELEASE_BRANCH_SOURCE_DEFAULT="main"

function usage() {
  echo "$0 -v <version number> [-b <release source branch name>] [-r <git repo url>] [-f] [-d]"
  echo
  echo "    -v <version number>"
  echo "      The numerical version, in semver format, of the release."
  echo "        Eg. 0.3.5"
  echo "    -b <release source branch name>"
  echo "      The name of the branch from which release source should be obtained."
  echo "      (default=${RELEASE_BRANCH_SOURCE_DEFAULT})"
  echo "    -r <git repo url>"
  echo "       The git repo url to use."
  echo "       (default=${GIT_REPO_DEFAULT})"
  echo "    -f"
  echo "      Determines whether or not release tags should be forcibly pushed."
  echo "      Note that this will overwrite any existing tags; use with caution."
  echo "      (default=disabled)"
  echo "    -d"
  echo "      Enable script debugging. This enables script output (stdout+stderr)."
  echo
}

function finish() {
  if [ ! -z ${TEMPDIR+x} ]; then
    rm -rf ${TEMPDIR} >& ${REDIRECT}
  fi
}

function main() {
    local RELEASE_VERSION=
    local RELEASE_BRANCH_SOURCE=${RELEASE_BRANCH_SOURCE_DEFAULT}
    local FORCE=
    local GIT_REPO=${GIT_REPO_DEFAULT}
    
    while getopts ":v:b:r:fd" opt; do
    case ${opt} in
      v)
        RELEASE_VERSION="${OPTARG}"
        ;;
      b)
        RELEASE_BRANCH_SOURCE="${OPTARG}"
        ;;
      r)
        GIT_REPO="${OPTARG}"
        ;;
      f)
        FORCE=" -f"
        ;;
      d)
        DEBUG=1
        REDIRECT=/dev/tty
        ;;
      *)
        ;;
        esac
    done

    if [ -z ${RELEASE_VERSION+x} ]; then
      echo "missing release version"
      usage
      exit 1
    fi

    local RELEASE_VERSION_TAG=v${RELEASE_VERSION}
    local RELEASE_NAME=${FEATURE}-${RELEASE_VERSION}
    local RELEASE_DIR_SOURCE=${FEATURE}-release-${RELEASE_VERSION}
    local RELEASE_DIR=${RELEASE_NAME}
    local RELEASE_ARCHIVE=${RELEASE_NAME}.tar.xz

    TEMPDIR=$(mktemp -d)
    pushd ${TEMPDIR} >& ${REDIRECT}
    echo "checking out branch '${RELEASE_BRANCH_SOURCE}' from ${GIT_REPO}"
    git clone ${GIT_REPO} --branch ${RELEASE_BRANCH_SOURCE} ${RELEASE_DIR_SOURCE} >& ${REDIRECT}
    pushd ${RELEASE_DIR_SOURCE} >& ${REDIRECT}
    echo "tagging as ${RELEASE_VERSION_TAG}"
    git tag ${RELEASE_VERSION_TAG} ${FORCE} >& ${REDIRECT}
    git push origin refs/tags/${RELEASE_VERSION_TAG} ${FORCE} >& ${REDIRECT}

    echo "preparing release archive"
    git config tar.tar.xz "xz -c"
    git archive --format=tar.xz --prefix=${RELEASE_NAME}/ ${RELEASE_VERSION_TAG} > ${RELEASE_ARCHIVE}
    echo "created release archive ${RELEASE_ARCHIVE} -> $(sha256sum ${RELEASE_ARCHIVE} | awk '{print $1}')"
}

main "$@"
finish 