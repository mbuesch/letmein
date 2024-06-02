# letmein - Authenticated port knocking

[Homepage](https://bues.ch/)

[Git repository](https://bues.ch/cgit/letmein.git)

## Building

Run the `build.sh` script to build letmein.

The build requires the `cargo-audit` and `cargo-auditable` Rust crates installed:

```sh
cargo install cargo-audit cargo-auditable
```

After installing all build dependencies, run the build script:

```sh
./build.sh
```

## Installing

### Server

After building, run the `install-server.sh` to install the letmeind server to `/opt/letmein/`:

```sh
./install-server.sh
```

This step is optional, if you don't need the server.

Installing the server will also install the service into systemd and start the service.

### Client

Then run the `install-client.sh` to install the letmein client to `/opt/letmein/`:

```sh
./install-client.sh
```

This step is optional, if you don't need the client.

# License

Copyright (c) 2024 Michael Büsch <m@bues.ch>

Licensed under the Apache License version 2.0 or the MIT license, at your option.
