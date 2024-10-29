# Building and installing letmein

## Prerequisites

The Rust compiler must be installed to build letmein.
It is recommended to use the latest version of the stable Rust compiler.
But Rust versions down to and including Rust 1.75 are supported by letmein.

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

## Downloading letmein

Either download the release source tarball and gpg signature from
[the official release directory](https://bues.ch/releases/letmein/)

or download the release source code from the
[Github Release section](https://github.com/mbuesch/letmein/releases)

or clone the
[git repository](https://github.com/mbuesch/letmein)
to get the latest development version.

## Building letmein

Run the `build.sh` script to build letmein.

After installing all build prerequisites, run the build script:

```sh
./build.sh
```

## Installing letmein

### Install client

Then run the `install-client.sh` to install the letmein client to `/opt/letmein/`:

```sh
./install-client.sh
```

The client is used to send a knock packet to the server.

### Install server

#### Prepare user and group for the server

The public network facing part of the letmein server runs with reduced privileges to reduce the attack surface.

For this to work, the user `letmeind` and the group `letmeind` have to be present in `/etc/passwd` and `/etc/group`.
It is recommended for this user to not have a shell and home assigned and therefore not be a login-user.

You can use the following helper script to create the user and group in your system:

```sh
./create-user.sh
```

#### Install the server and systemd units

After building and creating the `letmeind` system user, run the `install-server.sh` to install the letmeind server to `/opt/letmein/`:

```sh
./install-server.sh
```

Installing the server will also install the service and socket into systemd and start the letmeind server.

The server is used to receive knock packets from the client.
Upon successful knock authentication, the server will open the knocked port in its `nftables` firewall.

## Installing with `cargo install` from crates.io

Alternatively, you can install letmein, letmeind and letmeinfwd with `cargo install` from [crates.io](https://crates.io/).

Note that there are a few important differences when using `cargo install` instead of the `install*.sh` scripts from above:

- letmein will look for configuration files in `/etc` instead of `/opt/letmein/etc`.
- The system user and group `letmeind` will not be installed in the operating system. The user and group are required for server operation.
- The systemd sockets and services will not be installed in the operating system.

You may use `cargo install` to install the `letmein` client application.
But it is *not* recommended to use `cargo install` to install the `letmeind` and `letmeinfwd` server daemons.

## Arch Linux: Installing from AUR

If you use [Arch Linux](https://archlinux.org/), then you can install the client and the server from [AUR](https://aur.archlinux.org/packages/letmein).
The AUR package will install the configuration to `/etc` and the binaries to `/usr/bin`.

(The AUR package is maintained by a third party maintainer. Thanks!)

# Uninstalling

## Installed by `install-*.sh`

If you installed letmein with the `install-*.sh` scripts (see above), run the following commands to completely remove letmein from your system.

WARNING: This also removes the configuration files.

```sh
systemctl stop letmeind.socket
systemctl stop letmeind.service
systemctl stop letmeinfwd.socket
systemctl stop letmeinfwd.service
systemctl disable letmeind.service
systemctl disable letmeind.socket
systemctl disable letmeinfwd.service
systemctl disable letmeinfwd.socket

rm /etc/systemd/system/letmeind.socket
rm /etc/systemd/system/letmeind.service
rm /etc/systemd/system/letmeinfwd.socket
rm /etc/systemd/system/letmeinfwd.service
rm -r /opt/letmein
```

## Installed by other method

If you used another method please refer to the documentation of your install method.
