#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
state_dir=${XDG_STATE_HOME:-"$HOME/.local/state"}/bug-bounty-tracker
mkdir -p "$state_dir"
cd "$project_dir"

exec 9>"$state_dir/releases.lock"
if ! flock -n 9; then
    exit 0
fi
exec "$project_dir/.venv/bin/python" -m backend.github.releases > "$state_dir/releases.log" 2>&1
