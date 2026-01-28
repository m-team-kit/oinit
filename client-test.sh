#!/bin/bash

# Tests ssh client with oinit.
#
# Assumes $HOST $PORT to be under oinit control

HOST="hpc.example.org"
PORT="1022"
OP="egi"
export OINIT_DEBUG="jawoll"


MY_INTERNAL_AT=$(oidc-token $OP)

echo "Testing for $HOST:$PORT with $OP"
echo "Access Token: ${MY_INTERNAL_AT}"

# ssh $HOST -p $PORT "id"

clean_env () {
# CLEAN the environment
    for i in  \
        ACCESS_TOKEN \
        BEARER_TOKEN \
        OIDC \
        OS_ACCESS_TOKEN \
        OIDC_ACCESS_TOKEN \
        ; do
        unset $i
    done
    rm -f ~/.ssh/oinit_${HOST}_${PORT}*

    rm -f "${BEARER_TOKEN_FILE}"
    rm -f "${XDG_RUNTIME_DIR}"/bt_u"${UID}"
    rm -f /tmp/bt_u"${UID}"
}
info(){
    IFS='
'
    echo -e "\n\n##########################################################################"
    printf "# %-70s\n" "$@"
    # echo -e "##########################################################################"
    echo ""
    unset ifs
}

handle_error(){
    echo "\nERROR ERROR ERROR ERROR ERROR ERROR ERROR ERROR ERROR\n"
    reset_environment
    exit 2
}
reset_environment(){
    export SSH_AUTH_SOCK="$BAK_SSH_AUTH_SOCK"
    export SSH_AGENT_PID="$BAK_SSH_AGENT_PID"
    export GPG_AGENT_INFO="$BAK_GPG_AGENT_INFO"
    export OIDCD_PID="$BAK_OIDCD_PID"
    export OIDCD_PID_FILE="$BAK_OIDCD_PID_FILE"
    export OIDC_SOCK="$BAK_OIDC_SOCK"
    unset OINIT_DEBUG
}
# Backup environment
BAK_OIDCD_PID="$OIDCD_PID"
BAK_OIDCD_PID_FILE="$OIDCD_PID_FILE"
BAK_OIDC_SOCK="$OIDC_SOCK"
BAK_SSH_AUTH_SOCK="$SSH_AUTH_SOCK"
BAK_SSH_AGENT_PID="$SSH_AGENT_PID"
BAK_GPG_AGENT_INFO="$GPG_AGENT_INFO"


# make sure we don't use ssh-agent for now
unset SSH_AUTH_SOCK
unset SSH_AGENT_PID
unset GPG_AGENT_INFO

clean_env
info "Using BEARER_TOKEN environment variable"
export BEARER_TOKEN="${MY_INTERNAL_AT}"
ssh $HOST -p $PORT "id" || handle_error

clean_env
info "Using BEARER_TOKEN_FILE environment variable"
BEARER_TOKEN_FILE=$(mktemp)
echo "${MY_INTERNAL_AT}" > ${BEARER_TOKEN_FILE}
ssh $HOST -p $PORT "id" || handle_error

clean_env
info "Using XDG_RUNTIME_DIR"
echo "${MY_INTERNAL_AT}" > ${XDG_RUNTIME_DIR}/bt_u${UID}
ssh $HOST -p $PORT "id" || handle_error

clean_env
info "Using /tmp/bt_u${UID}"
echo "${MY_INTERNAL_AT}" > /tmp/bt_u${UID}
ssh $HOST -p $PORT "id" || handle_error

clean_env
AT="${MY_INTERNAL_AT}"
info "Use without access to oidc-agent. Use this token:\\n $AT"



unset OIDCD_PID
unset OIDCD_PID_FILE
unset OIDC_SOCK
ssh $HOST -p $PORT "id" || handle_error
export OIDCD_PID="$BAK_OIDCD_PID"
export OIDCD_PID_FILE="$BAK_OIDCD_PID_FILE"
export OIDC_SOCK="$BAK_OIDC_SOCK"

clean_env
info "Re-enabled oidc-agent"
export ACCESS_TOKEN="${MY_INTERNAL_AT}"

ssh $HOST -p $PORT "id" || handle_error

info "Reuse certificate (from file in ~/.ssh/oinit_${HOST}_${PORT}-cert.pub)"
ssh $HOST -p $PORT "id" || handle_error

clean_env
info "Using env: ACCESS_TOKEN to store cert in ssh-agent"
export ACCESS_TOKEN="${MY_INTERNAL_AT}"
echo -n "Starting temporary ssh-agent: "
eval $(ssh-agent)
echo ""
ssh $HOST -p $PORT "id" || handle_error

info "Reuse certificate from ssh-agent"
ssh $HOST -p $PORT "id" || handle_error


kill "$SSH_AGENT_PID"
unset SSH_AUTH_SOCK
unset SSH_AGENT_PID

reset_environment

