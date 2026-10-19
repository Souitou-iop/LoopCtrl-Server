#!/bin/sh
# Render loopctrl-relay.service from the template next to this script.
#
#   CODE_DIR=/opt/loopctrl-server/current ENV_FILE=/etc/loopctrl-relay/relay.env \
#   STATE_DIR=/var/lib/loopctrl-relay connect/relay/systemd/render-unit.sh > /etc/systemd/system/loopctrl-relay.service
#
# Variables (defaults in brackets):
#   CODE_DIR   checkout or release of LoopCtrl-Server        [/opt/loopctrl-server/current]
#   ENV_FILE   relay.env with the operator token              [/etc/loopctrl-relay/relay.env]
#   STATE_DIR  directory holding state.json (written in place) [/var/lib/loopctrl-relay]
#   PYTHON     Python 3.10 or newer                            [python3 on PATH]
#   BIND PORT  listen address                                  [127.0.0.1 8787]
#   USER_NAME  service user; must own STATE_DIR                [root]
set -eu
here=$(cd "$(dirname "$0")" && pwd)
CODE_DIR=${CODE_DIR:-/opt/loopctrl-server/current}
ENV_FILE=${ENV_FILE:-/etc/loopctrl-relay/relay.env}
STATE_DIR=${STATE_DIR:-/var/lib/loopctrl-relay}
PYTHON=${PYTHON:-$(command -v python3)}
BIND=${BIND:-127.0.0.1}
PORT=${PORT:-8787}
USER=${USER_NAME:-root}

"$PYTHON" -c 'import sys; sys.exit(sys.version_info < (3, 10))' \
  || { echo "render-unit.sh: $PYTHON is older than 3.10" >&2; exit 1; }

sed -e "s|@CODE_DIR@|$CODE_DIR|g" -e "s|@ENV_FILE@|$ENV_FILE|g" \
    -e "s|@STATE_DIR@|$STATE_DIR|g" -e "s|@PYTHON@|$PYTHON|g" \
    -e "s|@BIND@|$BIND|g" -e "s|@PORT@|$PORT|g" -e "s|@USER@|$USER|g" \
    "$here/loopctrl-relay.service.in"
