#!/usr/bin/sh

# parse flag -y
while getopts ":y" opt; do
    case ${opt} in
    y)
        yes_all=true
        ;;
    \?)
        ;;
    esac
done

confirm() {
    printf "%s [y/N] " "${1:-Are you sure?}"
    read -r response
    case "$response" in
    [yY][eE][sS] | [yY])
        true
        ;;
    *)
        false
        ;;
    esac
}

# input with default
printf "Enter the path to install sshrelay [/usr/local/bin]: "
read -r install_path
install_path=${install_path:-/usr/local/bin}

[ -z "$yes_all" ] && (confirm "Do you want to install sshrelay to ${install_path}?" || exit 0)

# check if the path exists
if [ ! -d "${install_path}" ]; then
    [ -z "$yes_all" ] && (confirm "The path ${install_path} does not exist. Do you want to create it?" || exit 0)
    mkdir -p "${install_path}"
fi

if [ ! -w "${install_path}" ]; then
    printf "You don't have write permission to %s. Try with sudo\n" "${install_path}"
    exit 1
fi
if [ -f "${install_path}/sshrelay" ]; then
    [ -z "$yes_all" ] && (confirm "sshrelay is already installed. Do you want to overwrite it?" || exit 0)
fi


binary="sshrelay-"
case "$(uname -s)" in
Darwin)
    binary="${binary}darwin"
    ;;
Linux)
    binary="${binary}linux"
    ;;
CYGWIN* | MINGW32* | MSYS* | MINGW*)
    binary="${binary}windows"
    ;;
*)
    printf "Unknown OS: %s, go fix yourself\n" "$(uname -s)"
    exit 1
    ;;
esac

case "$(uname -m)" in
x86_64 | amd64)
    binary="${binary}-amd64"
    ;;
aarch64 | arm*)
    binary="${binary}-arm64"
    ;;
*)
    printf "Unknown or unsupported architecture: %s\n" "$(uname -m)"
    exit 1
    ;;
esac



query=$(cat <<EOF
  .assets[]
  | select(
    .name
    | test("${binary}")
  )
  | .browser_download_url
EOF
)

binURL=$(curl \
  -s https://api.github.com/repos/prochac/sshrelay/releases/latest \
  | jq -r "$query"
)

wget -q -O "${install_path}/sshrelay" "$binURL"
chmod +x "${install_path}/sshrelay"

echo "Successfully installed to ${install_path}/sshrelay"

[ -z "$yes_all" ] && (confirm "Do you want to create a systemd service for sshrelay?" || exit 0)

systemd_service="\
[Unit]
Description=SSH Relay Service
After=network.target

[Service]
Type=simple
ExecStart=\${full_bin_path} \\
    --host-key /usr/local/etc/sshrelay/ssh_host_rsa_key \\
    --host-key /usr/local/etc/sshrelay/ssh_host_ed25519_key \\
     --generate-host-keys \\
#    --user bob \\
#    --public-key /home/bob/.ssh/id_rsa.pub \\
    --port 22
KillMode=process
Restart=always
SyslogIdentifier=sshrelay

[Install]
WantedBy=multi-user.target
"

export full_bin_path="${install_path}/sshrelay"
echo "$systemd_service" | envsubst > /etc/systemd/system/sshrelay.service
systemctl daemon-reload

echo "Successfully created systemd service sshrelay"
echo "Please edit /etc/systemd/system/sshrelay.service to add access to some users"
echo "Then don't forget to run 'systemctl daemon-reload' to reload the service"

[ -z "$yes_all" ] && (confirm "Do you want to start the sshrelay service?" || exit 0)
systemctl enable sshrelay
systemctl start sshrelay
systemctl status sshrelay
