# Letmein configuration files

Letmein includes two configuration files.
One for the server and one for the client.

If you installed letmein via `install.sh`, then the configuration files can be found in:

- server: `/opt/letmein/etc/letmeind.conf`
- client: `/opt/letmein/etc/letmein.conf`

If you installed letmein via distribution package or by other means, the configuration files are probably located in `/etc`:

- server: `/etc/letmeind.conf`
- client: `/etc/letmein.conf`

The format of the configuration files is a very simple `ini`-style format.
The files have multiple `[SECTIONS]` with `options=` and `# comments`.

# Common configuration parts

The server and client configuration files are very similar and contain common parts.

## `[GENERAL]`

### `debug`

The `debug` option can have the values `true` or `false.
Setting this option to `true` will enable verbose debug messages to the console and system log (e.g. `journalctl`).

Setting this option to `true` is a good idea, if you are configuring letmein for the first time on a machine.
It will show you exactly which actions are done to the firewall.

### `port`

The `port` option specifies the control port letmein will listen on.
This is the public internet facing port of the daemon.
All communication between the client and the server will happen on this port.

You do *not* have to manually open the firewall for this port.
Letmein will open this port by itself when it's up and running.

### `seccomp`

The `seccomp` option turns [Seccomp](https://en.wikipedia.org/wiki/Seccomp) security hardening on or off.

The option can one of three possible values:

- `off`: Seccomp turned off.
- `log`: Seccomp turned off, but access of prohibited syscalls will be logged to syslog.
  Logging is useful for debugging and initial configuration.
  It will *not* provide any security hardening.
- `kill`: Seccomp turned on.
  Letmeind will be killed if prohibited syscalls are called.

It is recommended to set this option to `seccomp=log` and then watch the syslog, if there are any seccomp warning messages.
If there are no warning messages, it is recommended to set the option to `seccomp=kill` to enable the security hardening.

If you see seccomp warning messages or seccomp kills, please open an [issue](https://github.com/mbuesch/letmein/issues).

Currently this is a server-only option that only affects the network facing daemon `letmeind`.
In future seccomp support could be added to `letmeinfwd` and the client, too.

## `[KEYS]`

TODO

## `[RESOURCES]`

TODO

# Server specific configuration parts

## `[NFTABLES]`

### `family`

This is the nftables family of the table/chain that letmein should control.

This usually should be set to `family=inet` to allow IPv4 and IPv6 rules to be installed.

If you don't know what this means, please use the example [nftables.conf](nftables.conf) that comes with letmein and set this option to the default `family=inet`.

For more information about the nftables firewall, please see the nftables documentation.

### `table`

This is the name of the nftables table that contains the chain that letmein should control.

In the example configuration the table is `table=filter`.

If you don't know what this means, please use the example [nftables.conf](nftables.conf) that comes with letmein and set this option to the default `table=filter`.

For more information about the nftables firewall, please see the nftables documentation.

### `chain-input`

This is the name of the nftables chain that letmein should control.

In the example configuration the table is `chain-input=LETMEIN-INPUT`.

If you don't know what this means, please use the example [nftables.conf](nftables.conf) that comes with letmein and set this option to the default `chain-input=LETMEIN-INPUT`.

For more information about the nftables firewall, please see the nftables documentation.

### `timeout`

The `timeout` option specifies the knock-open firewall rule timeout, in seconds.
Knocked-open ports will be closed again this many seconds after the knocking.

This is the time you have to connect to the opened port.

Typically the time doesn't have to be that long.
For most applications the port does only have to be open for the initial connection phase and communication can continue even after the rule has timed out and closed the port.
Established connections will stay active when the port is closed.

It is recommended to set this to a small duration of e.g. one minute `timeout=60` or ten minutes `timeout=600`.
