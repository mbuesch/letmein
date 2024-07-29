# Reporting Security Issues

If you found a security vulnerability, you deserve all the credit.
Please feel free to have a good ROFLMAO over my broken design.
I deserve all the blame and I have all the responsibility for fixing the problem.

I'd like to ask you to fully disclose the details of your valuable findings via GitHub Security Advisory [Report a Vulnerability](https://github.com/mbuesch/letmein/security/advisories/new) tab or report it privately via [security@bues.ch] to me.

If you found a severe security vulnerability, a private disclosue is preferred.
This is to protect our users from [0-Day](https://en.wikipedia.org/wiki/Zero-day_vulnerability) exploits.
I will always publish vulnerabilities to the public after finding a proper fix.

# Security hardening

The public network facing daemon `letmeind` supports the security hardening technique [seccomp](https://en.wikipedia.org/wiki/Seccomp).

Seccomp basically disables all Operating System Calls (syscalls) that are not required by the application.

By default seccomp is disabled in `letmeind`.
To enabled it, edit `/opt/letmein/etc/letmeind.conf` and set the seccomp option:

```
[GENERAL]
seccomp = kill
```

Setting the `seccomp` option to `kill` will fully enable seccomp.
If the `letmeind` daemon executes a syscall that has not explicitly been allowed by the hard-coded allow-list, the Linux kernel will immediately kill `letmeind`.
That way attacker injected code cannot execute arbitrary syscalls that are not on the allow-list.

Alternatively, you can configure the `seccomp` option to `log`.
This will **not** give you any bug-exploit protection, but it will print a kernel log error message, if a syscall is called that is not on the letmein allow-list.
This is useful for debugging.

Note that depending on your Linux Distribution you might be getting false seccomp kills, because the allow-list doesn't include a required syscall.
In this case, please open a Github Issue on letmein.

Seccomp is currently only supported on the `x86_64` and `aarch64` CPU architectures.

The seccomp feature of letmeind has been tested with Debian Linux Stable and Unstable.
