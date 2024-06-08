# letmein - Authenticated port knocking

Letmein is a simple port knocker with a simple and secure authentication mechanism.

It can be used to hide services on a server behind a knock authentication to reduce the attack surface of a service.
The service will not be accessible unless a knock authentication is successful.
In case of a successful knock, the letmeind server will only open the knocked port for the client IP address that performed the knocking.
Machines with different IP addresses still won't have access to the protected service.

Machines that can't successfully authenticate the knock sequence won't be able to access the protected service.

Letmein requires an `nftables` based firewall. It will *not* work with `iptables`.

[Homepage](https://bues.ch/h/letmein)

[Git repository](https://bues.ch/cgit/letmein.git)

[Github repository](https://github.com/mbuesch/letmein)

## Usage example: Put OpenSSH (sshd) access behind a knock authentication barrier

On the server install the letmein server software (see sections below).

On the client install the letmein client software (see sections below).

Please read the [nftables.conf](nftables.conf) example configuration file provided with this project.
Adding a letmein specific input chain to your existing `nftables` configuration is required.
Modify your `nftables.conf` accordingly.

Generate shared secret key and a user identifier to be installed on the server and client with the following client command:

```sh
letmein gen-key -u 00000000
```

The gen-key command will print the generated key string to the console.
By default this will generate a secure random key for the user identifier `00000000`.
You can manually edit the user identifier, if you want, or you can just leave it as-is.

Add the generated string (user identifier and the shared secret) to the server configuration in `/opt/letmein/etc/letmeind.conf`.
Put the generated key string together with the user identifier into the `[KEYS]` section of the configuration file.

Add the same generated string (user identifier and shared secret) to the client configuration in `/opt/letmein/etc/letmein.conf`.
Put the generated key string together with the user identifier into the `[KEYS]` section of the configuration file.

Create a `resource` in the server that describes the `sshd` port that can be opened.
In the `[RESOURCES]` section of the server configuration file `/opt/letmein/etc/letmeind.conf` all ports that may be opened must be specified. A resource consists of a resource identifier followed by a port identifier like that:

```
[RESOURCES]
00000022 = port: 22
```

The resource identifier is an 8 digit hexdecimal number. In this example it is 22(hex), but it can be any number. It just has to be the same number on the server and the client. After `port:` the port number (in decimal) that can be knocked-open is specified.

Add the same resource identifier with the same resource identifier and the same port number to the client configuration in `/opt/letmein/etc/letmein.conf`.

Restart the letmein server:

```sh
systemctl restart letmeind.service
```

Now remove the `sshd` port (22) `accept` from your `nftables.conf`.
Letmein will install such a rule dynamically into the letmein input chain after successful knock authentication.
Then restart nftables:

```sh
systemctl restart nftables.service
```

Done! You should now be able to knock-open the `sshd` port on your server:

```sh
# This must fail! No successful knock authentication, yet.
# If this does not fail, check if you have removed the sshd accept rule from nftables.conf.
ssh your-server.com

# Knock-open port 22 (sshd) on the server using user-id/key 00000000:
# (You do not have to specify -u 00000000 if that is your default user (see config).)
letmein knock -u 00000000 your-server.com 22

# Now you should be able to ssh into your server successfully:
ssh your-server.com
```

## Prerequisites

The Rust compiler must be installed to build letmein.
It is recommended to use the latest version of the stable Rust compiler:

[Rust installer](https://www.rust-lang.org/tools/install)

The Rust installer will install the compiler and the build tool `cargo`.

The build requires the additional `cargo-audit` and `cargo-auditable` tools to be installed.
Run this command to install both tools:

```sh
cargo install cargo-audit cargo-auditable
```

At runtime the nftables `nft` binary is required to be installed reachable in the `$PATH`.
On Debian please install the `nftables` package:

```sh
apt install nftables
```

## Building letmein

Run the `build.sh` script to build letmein.

After installing all build prerequisites, run the build script:

```sh
./build.sh
```

## Installing letmein

### Install server

After building, run the `install-server.sh` to install the letmeind server to `/opt/letmein/`:

```sh
./install-server.sh
```

Installing the server will also install the service and socket into systemd and start the letmeind server.

The server is used to receive knock packets from the client.
Upon successful knock authentication, the server will open the knocked port in its `nftables` firewall.

### Install client

Then run the `install-client.sh` to install the letmein client to `/opt/letmein/`:

```sh
./install-client.sh
```

The client is used to send a knock packet to the server.

## Internals and design goals

The main design goals of letmein are:

- It is implemented in a memory-safe programming language that makes certain classes of severe bugs impossible.
- The algorithms and implementation must be as simple as reasonably possible.
- It does not implement complicated cryptographic algorithms such as asynchronous public/private key crypto. It uses a shared secret together with HMAC/SHA3 for authentication instead.
- It has a replay protection. Replaying a knock packet sequence will not result in a successful authentication.
- It only opens the port for the IP address that made the knock request.
- Please read the code and comment on it. Feel free to open an issue, if you have questions, suggestions or requests. Please discuss the pros and cons of these design decisions. I am interested to hear your opinion.

# License

Copyright (c) 2024 Michael Büsch <m@bues.ch>

Licensed under the Apache License version 2.0 or the MIT license, at your option.
