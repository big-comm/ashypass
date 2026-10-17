#!/usr/bin/env bash
# Start a throwaway Apache mod_dav server on 127.0.0.1 for the WebDAV
# folder-sync test, run it, and remove everything afterwards.
#
#   scripts/webdav-test-server.sh          run the WebDAV tests
#   scripts/webdav-test-server.sh serve    keep a server up for manual tests
set -euo pipefail

modules=/usr/lib/httpd/modules
root=$(mktemp -d /tmp/ashypass-webdav.XXXXXX)
port=${ASHYPASS_TEST_WEBDAV_PORT:-18080}
password=$(head -c 12 /dev/urandom | base64 | tr -d '/+=')
mkdir -p "$root/data" "$root/logs"
htpasswd -bc "$root/users" tester "$password" >/dev/null 2>&1

cat >"$root/httpd.conf" <<CONF
ServerRoot "$root"
Listen 127.0.0.1:$port
ServerName 127.0.0.1
PidFile "$root/httpd.pid"
ErrorLog "$root/logs/error.log"
LoadModule mpm_event_module $modules/mod_mpm_event.so
LoadModule unixd_module $modules/mod_unixd.so
LoadModule authn_core_module $modules/mod_authn_core.so
LoadModule authn_file_module $modules/mod_authn_file.so
LoadModule authz_core_module $modules/mod_authz_core.so
LoadModule authz_user_module $modules/mod_authz_user.so
LoadModule auth_basic_module $modules/mod_auth_basic.so
LoadModule dav_module $modules/mod_dav.so
LoadModule dav_fs_module $modules/mod_dav_fs.so
DAVLockDB "$root/davlock"
DocumentRoot "$root/data"
<Directory "$root/data">
    Dav On
    AuthType Basic
    AuthName "test"
    AuthUserFile "$root/users"
    Require valid-user
</Directory>
CONF

httpd -f "$root/httpd.conf" -k start
trap 'httpd -f "$root/httpd.conf" -k stop; sleep 1; rm -rf "$root"' EXIT
sleep 1

if [ "${1:-}" = serve ]; then
    echo "WebDAV server: http://127.0.0.1:$port  user: tester  password: $password"
    echo "Files: $root/data   (Ctrl+C stops and removes everything)"
    while sleep 3600; do :; done
fi

export ASHYPASS_TEST_WEBDAV_URL="http://127.0.0.1:$port"
export ASHYPASS_TEST_WEBDAV_USER=tester
export ASHYPASS_TEST_WEBDAV_PASSWORD="$password"
cargo test -p ashypass-core --lib webdav -- --include-ignored "$@"
