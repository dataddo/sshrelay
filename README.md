# SSH Relay

This is a simple SSH server that accepts just port forwarding requests from any
SSH client, and forwards the connection to a target server. It is useful when
you want to expose a server that is behind a firewall or NAT, and don't want to
run a full OpenSSH server, with all the security implications that may come with
it.

## Usage

If you want to set up users, you must use the `-public-key` or
`-public-key-path` to specify the public key file for the user. The number of
`-user` flags and `-public-key` or `-public-key-path` flags must be the same.

```
Usage of sshrelay:
  -host string
        Hostname or IP address to listen on (default "0.0.0.0")
  -host-key value
        Host key file (default "/etc/ssh/ssh_host_rsa_key")
  -port uint
        Port to listen on (default 22)
  -public-key value
        Public key file for user
  -public-key-path value
        Path to public key file for user
  -user value
        Allowed user
```
