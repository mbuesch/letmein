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

The `debug` option can have the values `true` or `false`.
Setting this option to `true` will enable verbose debug messages to the console and system log (e.g. `journalctl`).

Setting this option to `true` is a good idea, if you are configuring letmein for the first time on a machine.
It will show you exactly which actions are done to the firewall.

This option defaults to `debug=false`, if it is absent from the configuration.

### `port`

The `port` option specifies the control port letmein will listen on.
This is the public internet facing port of the daemon.
All communication between the client and the server will happen on this port.

You can select to listen on a TCP port or an UDP port or both.

On the server this option specifies which port it will listen on.

On the client this option specifies the default port used to connect to the server.
The user can override the port on the client command line.
See `letmein knock --help` for more information.

You do *not* have to manually open the firewall for this port.
Letmein will open this port by itself when it's up and running.

This option defaults to `port=5800`, if it is absent from the configuration.

#### TCP

If the port configuration is just a plain number such as `port=5800` or if TCP is explicitly specified such as `port=5800/tcp`, then the port will be a TCP port.

#### UDP

If the port configuration explicitly specifies UDP such as `port=5800/udp`, then the port will be a UDP port.

#### TCP + UDP

If the port configuration explicitly specifies TDP,UDP such as `port=5800/udp,tcp`, then the port will be a TCP port and a UDP port.

For the server this means it will listen on both TCP and UDP.

For the client this means that it will connect to the server over TCP, unless there is a command line override via `--server-port-udp`.

### `control-timeout`

The `control-timeout` option specifies the timeout for receiving and sending messages on the control port.
If the timeout is exceeded, the TCP connection will be aborted.

On the server this option aborts client connections that don't make progress during the authentication proctocol.
This kicks out clients that don't make progress from the limited number of connections available.

On the client this option allows for better error messages to the user by aborting authentication attempts that don't make any progress.

Don't choose a too small timeout.
Otherwise the authentication handshake will fail over very slow network connections.

This option defaults to `control-timeout=5.0` seconds, if it is absent from the configuration.

### `control-error-policy`

The `control-error-policy` error policy specifies how to communicate control protocol errors to the client.

If the policy is set to `always`, then error messages will always be transmitted to the connected client.

If the policy is set to `basic-auth`, then error messages are suppressed unless the connected client has passed basic authentication.

If the policy is set to `full-auth`, then error messages are suppressed unless the connected client has passed full authentication.

Setting the policy to `basic-auth` or `full-auth` means that unauthenticated clients don't get error responses.
This helps to not reveal what service is running on the control port to malicious scanner clients.
This enables a more stealth operation of the server.

The disadvantage of setting this to `basic-auth` or `full-auth` is that legitimate clients might not always receive a proper error message and end up in a network timeout instead.

What is `basic-auth` and what is `full-auth`?

All messages during the control communication are authenticated with a secret key and an authentication algorithm.
However, the first control messages before the full challenge-response handshake has been completed are not replay-safe.
That is what `basic-auth` is.

`full-auth` is everything after the challenge-response handshake between server and client has completed successfully.

For the purpose of enabling a stealth operation with `control-error-policy` the `basic-auth` is enough.
During the challenge-response handshake the presence of the server has been revealed anyway.

Possible values: `always`, `basic-auth`, `full-auth`

The recommended value is: `basic-auth`

This option defaults to `control-error-policy=always`, if it is absent from the configuration.

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

This option defaults to `seccomp=off`, if it is absent from the configuration.

## `[KEYS]`

This section holds a table of user identifiers with their corresponding secret shared keys.

There is an arbitrary amount of options of the following style in this section:

```
USER = KEY
```

Where the `USER` is a 32 bit hexadecimal number and the `KEY` is a 256 bit hexadecimal number.

The `USER` can be any 32 bit hexadecimal number.
It's up to the administrator to choose a number.
It is just an identifier to identify the user.
There isn't any other meaning to this value.
Please note that the user identifier is transmitted in clear text (unencrypted) over the network.
Therefore, the user identifier shall not be considered to be secret.
Please pick any number that makes sense for your environment, but ensure that it is not secret.

The `KEY` is a secure random 256 bit shared key.
The key shall be generated with the `letmein gen-key` command to generate a truly random and secure unique key.
Modifying the generated key is discouraged.
Humans are bad at creating random keys.
Please do not try to manually create your own key by typing it down or modifying an existing key.
Doing so will probably result in an extremely low quality key.
The KEY is **not** transmitted in clear text over the network.
A secure [HMAC](https://en.wikipedia.org/wiki/HMAC) algorithm is used instead.

The key is a shared secret between the client(s) and the server.
Only the server and the client(s) shall have knowledge of the key.

The key is what authenticates the user to the server.
Therefore, it is important that the key is kept secret at both the client end and the server end.
Possession of the key is what authenticates the client to the server.

If a client wants to knock a port open on a server, the client and the server must share the same `USER = KEY` entry.
This configuration entry is what essentially authorizes the client to knock a port open on the server.

## `[RESOURCES]`

This section holds a table of knock-able ports.

There is an arbitrary amount of options of the following style in this section:

```
ID = port: ...
```

or

```
ID = port: ... / users: ... , ...
```

The first variant declares a resource usable by all users.

The second variant declares a resource usable only by a subset of users.

The `ID` can be any 32 bit hexadecimal number.
It's up to the administrator to choose a number.
It is just an identifier to identify the resource.
There isn't any other meaning to this value.
Please note that the resource identifier is transmitted in clear text (unencrypted) over the network.
Therefore, the resource identifier shall not be considered to be secret.
Please pick any number that makes sense for your environment, but ensure that it is not secret.

The `port` is the TCP/UDP port number that this resource represents.
It can be any port number between 0 and 65535.
When this resource is successfully authenticated from a knocking client, the port number will be opened in the firewall.
Only ports for which a resource has been configured here are knock-able.
Similarly, any opened port can be explicitly closed using the `letmein close` command with the same resource information.

By default the port will only be opened for TCP.
If you want TCP+UDP or UDP only, then specify this as flags in the resource.
See examples below.

A resource can optionally be restricted to one or multiple `users`.
If the `users` list is not given, then the resource is unrestricted and any successfully authenticated user can knock it open or close it.
If a `users` list is given, then only these users can knock the port open or close it.
The `users` list is just a comma separated list of user identifiers.
See `[KEYS]` section above for more information about user identifiers.

If a client wants to knock a port open or close a previously opened port on a server, the client and the server must share a compatible resource entry for the port.

Example resources:

```
# Resource: TCP port 1234.
00000001 = port: 1234

# Resource: TCP port 1234.
00000001 = port: 1234 / tcp

# Resource: TCP and UDP port 1234.
00000001 = port: 1234 / tcp,udp

# Resource: UDP port 1234.
00000001 = port: 1234 / udp

# Resource: TCP and UDP port 1234. Only for users 00000005 and 00000006
00000001 = port: 1234 / tcp,udp / users: 00000005,00000006
```

# Server specific configuration parts

## `[NFTABLES]`

### `exe`

Path to the `nft` nftables executable.

If this is an absolute path (with leading slash), then `$PATH` will not be searched.
If this is a relative path (no leading slash), then `$PATH` and/or the current working directory will be searched.

This option can be used to either use an `nft` executable that cannot be found in `$PATH`.
Or it can be used to harden against injection of forged a `nft` executable somewhere else in the `$PATH`.

It is recommended to set this option to the abolute path of the `nft` executable of your Linux distribution.
E.g.: `exe = /usr/sbin/nft`

There are a couple of minor restrictions for what the `exe` path can be.
These restrictions are believed to be non-critical in actual real world use cases, but are listed here for completeness:

- The path can't start or end with white space. White space at the start or at the end will be trimmed.
- The path can't end with a backslash.
- The path can't contain a newline character.
- The path can't contain a non-UTF8 character.

This option defaults to `exe=nft`, if it is absent from the configuration.

### `family`

This is the nftables family of the table/chain that letmein should control.

This usually should be set to `family=inet` to allow IPv4 and IPv6 rules to be installed.

If you don't know what this means, please use the example [nftables.conf](nftables.conf) that comes with letmein and set this option to the default `family=inet`.

For more information about the nftables firewall, please see the nftables documentation.

This option has no default and must be specified in the server configuration.

### `table`

This is the name of the nftables table that contains the chain that letmein should control.

In the example configuration the table is `table=filter`.

If you don't know what this means, please use the example [nftables.conf](nftables.conf) that comes with letmein and set this option to the default `table=filter`.

For more information about the nftables firewall, please see the nftables documentation.

This option has no default and must be specified in the server configuration.

### `chain-input`

This is the name of the nftables chain that letmein should control.

In the example configuration the table is `chain-input=LETMEIN-INPUT`.

If you don't know what this means, please use the example [nftables.conf](nftables.conf) that comes with letmein and set this option to the default `chain-input=LETMEIN-INPUT`.

For more information about the nftables firewall, please see the nftables documentation.

This option has no default and must be specified in the server configuration.

### `timeout`

The `timeout` option specifies the knock-open firewall rule timeout, in seconds.
Knocked-open ports will be closed again this many seconds after the knocking.

Alternatively, you can manually close a port before the timeout expires using the `letmein close` command with the same resource information that was used to open it.

This is the time you have to connect to the opened port.

Typically the time doesn't have to be that long.
For most applications the port does only have to be open for the initial connection phase and communication can continue even after the rule has timed out and closed the port.
Established connections will stay active when the port is closed.

It is recommended to set this to a small duration of e.g. one minute `timeout=60` or ten minutes `timeout=600`.

This option defaults to `timeout=600`, if it is absent from the configuration.
