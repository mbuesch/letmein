# Recommendations for distribution packaging

If you want to package the software for distribution, a few adjustments/patches are recommended:

- If you install default configuration files, you might want to adjust `[NFTABLES] exe = ...` to the absolute path of your `nft` binary. See [the configuration documentation](CONFIGURATION.md#exe) for more details.

- You probably want to install the systemd units under `/lib/systemd/system/` or similar, instead of `/etc`.

- The build environment variable `LETMEIN_CONF_PREFIX` sets the prefix for the configuration files.
  In a plain `cargo build` this will default to `/` meaning that `/etc/letmein{,d}.conf` will be the place for the configuration files.
  If you use the `build.sh` script, the prefix will be set to `/opt/letmein` instead.
  Meaning that the configuration files will be placed into `/opt/letmein/etc/`.

- Adjust the install prefix from `/opt` to something else that makes more sense for your distribution.
