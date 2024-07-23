# letmein - Authenticated port knocking

Letmein is a simple port knocker with a simple and secure authentication mechanism.
It can be used to harden against pre-authentication attacks on services like SSH, VPN, IMAP and many more.

Letmein hides services on a server behind a knock authentication barrier to reduce the attack surface of a service.
The service will not be accessible unless a knock authentication is successful.
In case of a successful knock, the letmeind server will only open the knocked port for the client IP address that performed the knocking.
Machines with different IP addresses still won't have access to the protected service.

Machines that can't successfully authenticate the knock sequence won't be able to access the protected service.
They will receive a TCP/ICMP `reject` on the protected service port with the provided example `nftables.conf`.
(You can also decide to `drop` the packets in your `nftables.conf` instead).

Letmein requires an `nftables` based firewall.
It will *not* work with `iptables`.
If you use an `iptables` based firewall, please convert to `nftables` before installing letmein.
There are descriptions about how to do that on the Internet.
It's not as hard and as much work as it sounds. :)

## Typical letmein operation flow

![image](pic/letmein_overview.png)

## Project links

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

Add the same resource with the same resource identifier and the same port number to the client configuration in `/opt/letmein/etc/letmein.conf`.

Restart the letmein server:

```sh
systemctl restart letmeind.service
```

Now remove your static `sshd` port (22) `accept` from your `nftables.conf` firewall configuration.
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

To automatically knock the port before connecting with ssh, you can add a `Match exec` rule to your `~/.ssh/config` file:

```
Match host your-server.com exec "letmein knock -u 00000000 your-server.com 22"
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

## Security notice: User identifiers and resource identifiers

Please be aware that the user identifiers and resource identifiers from the configuration files are transmitted over the network without encryption in clear text.

Make sure the user identifiers and resource identifiers do **not** include any private information.

These identifiers are merely meant to be an abstract identification for managing different `letmein` keys, installations and setups.

## Platform support

### Server

The server application `letmeind` is Linux-only, because it only supports `nftables` as firewall backend.

### Client

The client application `letmein` is portable and should run on all major platforms.
Tested platforms are:

- Linux
- Android, under [Termux](https://termux.dev/)
- Windows
- MacOS (build tested only)

## Internals and design goals

The main design goals of letmein are:

- It is implemented in a memory-safe programming language that makes certain classes of severe bugs impossible.
- The algorithms and implementation are as simple as reasonably possible.
- It does not implement complicated cryptographic algorithms such as asymmetric public/private key crypto. It uses a shared secret together with HMAC/SHA3 for authentication instead.
- It has a replay protection. Replaying a knock packet sequence does not result in a successful authentication.
- It only opens the port for the IP address that made the knock request. By default for both IPv4 and IPv6, if available. This behavior can be adjusted with the `-4` and `-6` client command line options.
- letmein does not link to libraries (.so) written in unsafe languages, except for the ones required by the operating system or by the Rust compiler. The only dynamically linked libraries are:
  - libc.so
  - libm.so
  - libgcc_s.so
  - linux-vdso.so
  - ld-linux-*.so
  - ld-android.so (Android only)
  - libdl.so (Android only)
  - libarmmem-*.so (Raspberry Pi only)

## Security analysis

The program has carefully been designed to be secure, to the best of my knowledge.

However, nobody is infallible.

- Please read the code and comment on it.
- Feel free to open an issue, if you have questions, suggestions or requests.
- Please discuss the pros and cons of the design decisions.

I am interested to hear your opinion.

If you found a security vulnerability, see [the vulnerability reporting process](SECURITY.md) for how to proceed.

### Known weaknesses

There are a couple of known weaknesses that exist in letmein.
In this paragraph we discuss why these weaknesses exist.

These weaknesses are not addressed by the design of letmein to make the design simpler.
It is a tradeoff between a simple design and a weakness that doesn't practically impact security.

It is believed that these weaknesses do **not** make letmein insecure in practical use.
The simple design is supposed to reduce the attack surface and as such improve security.

- **weakness**: The user identifiers and resource identifiers from the configurations are transmitted in plain text over the network.
  - **rationale**: The user identifiers and resource identifiers shall not include private or secret information.

- **weakness**: The first `Knock` packet is not protected against a replay attack.
  - **rationale**: It is true that the `Knock` packet can successfully be replayed by an attacker.
  But that doesn't mean much.
  The attacker will still not be able to successfully solve the `Challenge`.
  The authentication of the `Knock` is only in place, because it's easy to implement in the given design and it stops port knocks that don't have a key at all early.

- **weakness**: After a successful knock sequence from legitimate user an [MiM attacker](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) can use the knocked-open port, if she is able to use the same sender-IP-address as the legitimate user.
  - **rationale**: letmein only authenticates what happens during the knock sequence.
  What happens after the knock sequence once the firewall is opened for an IP address is completely out of scope of letmein.
  However, there is a time limit for how long the port is kept open after a successful knock sequence.
  After the knock sequence has been completed, there is only a limited amount of time an MiM could use it.

- **weakness**: If you knock a port open from behind a [NAT](https://en.wikipedia.org/wiki/Network_address_translation), then the port will be opened for the whole NATed network, because from the outside the NATed network has only one IP address.
  Everybody from within the NATed network will be able to access the knocked-open port.
  - **rationale**: The port is only open for a short and limited amount of time and there is supposed to be a second layer of security (see 2FA discussion below).
  While it's an unfortunate fact that the port will be open for the whole NATed network, this is still much better than having it open for the whole internet (without port knocker).

- **weakness**: The authentication key is a shared secret that is stored in plain text on the server and on the client.
  - **rationale**: It is true that an attacker that can successfully take over a server or client can steal the keys and authenticate future sessions.
  This is a tradeoff between implementing complicated public-private-key cryptography, the overall goal of what letmein is supposed to protect and simplicity of the design.
  letmein is **not** supposed to protect otherwise unprotected services.
  It is only supposed to be an *additional* barrier of security in an already secure system.
  Think of this as [2FA](https://en.wikipedia.org/wiki/Multi-factor_authentication).
  If an attacker could gain access to the letmein keys there are two scenarios:
  Either there is a second barrier of security (e.g. ssh server login) or all bets are lost anyway, because the attacker has full access already anyway.

- **weakness**: All users that can successfully authenticate to letmein can start to attack the protected service.
  - **rationale**: Yes, this is pretty much impossible to prevent.
  Letmein is supposed to prevent pre-authentication attacks.
  But it is possible to restrict users to certain ports.
  So that users can only authenticate with resources that they are explicitly allowed to in the server configuration.

- **weakness**: The wire protocol does not have mechanisms for future changes and updates.
  - **rationale**: While this makes updating to a new protocol version harder, it improves security by simplification of the design.
  It is not expected that there will be many incompatible protocol changes in the future.

# License

Copyright (c) 2024 Michael Büsch <m@bues.ch>

Licensed under the Apache License version 2.0 or the MIT license, at your option.
