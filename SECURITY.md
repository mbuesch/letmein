# Reporting Security Issues

If you found a security vulnerability, you deserve all the credit.
Please feel free to have a good ROFLMAO over my broken design.
I deserve all the blame and I have all the responsibility for fixing the problem.

I'd like to ask you to fully disclose the details of your valuable findings via GitHub Security Advisory [Report a Vulnerability](https://github.com/mbuesch/letmein/security/advisories/new) tab or report it privately via [security@bues.ch] to me.

If you found a severe security vulnerability, a private disclosue is preferred.
This is to protect our users from [0-Day](https://en.wikipedia.org/wiki/Zero-day_vulnerability) exploits.
I will always publish vulnerabilities to the public after finding a proper fix.

# Security hardening

The public network facing daemon `letmeind`, the firmware update daemon `letmeinfwd` and the client application `letmein` support the security hardening technique [seccomp](https://en.wikipedia.org/wiki/Seccomp).

Seccomp basically disables all Operating System Calls (syscalls) that are not required by the application.

By default seccomp is disabled.
To enabled it, edit `/opt/letmein/etc/letmeind.conf` and `/opt/letmein/etc/letmein.conf` and set the seccomp option:

```
[GENERAL]
seccomp = kill
```

Setting the `seccomp` option to `kill` will fully enable seccomp.
If letmein executes a syscall that has not explicitly been allowed by the hard-coded allow-list, the Linux kernel will immediately kill the process.
That way attacker injected code cannot execute arbitrary syscalls that are not on the allow-list.

Alternatively, you can configure the `seccomp` option to `log`.
This will **not** give you any bug-exploit protection, but it will print a kernel log error message, if a syscall is called that is not on the letmein allow-list.
This is useful for debugging.

Note that depending on your Linux Distribution you might be getting false seccomp kills, because the allow-list doesn't include a required syscall.
In this case, please open a Github Issue on letmein.

Seccomp is currently only supported on the `x86_64` and `aarch64` CPU architectures.

The seccomp feature of letmein has been tested with Debian Linux Stable and Unstable.

# Security analysis

The program has carefully been designed to be secure, to the best of my knowledge.

However, nobody is infallible.

- Please read the code and comment on it.
- Feel free to open an issue, if you have questions, suggestions or requests.
- Please discuss the pros and cons of the design decisions.

I am interested to hear your opinion.

If you found a security vulnerability, see [the vulnerability reporting process](SECURITY.md) for how to proceed.

## Known weaknesses

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

- **weakness**: If you knock a port open from behind a [NAT](https://en.wikipedia.org/wiki/Network_address_translation) or [cgNAT](https://de.wikipedia.org/wiki/Carrier-grade_NAT), then the port will be opened for the whole NATed network, because from the outside the NATed network has only one IP address.
  Everybody from within the NATed network will be able to access the knocked-open port.
  - **rationale**: The port is only open for a short and limited amount of time and there is expected to be a second layer of security in the protected service itself (e.g. ssh login; see 2FA discussion below).
  While it's an unfortunate fact that the port will be open for the whole NATed network, this is still much better than having it open for the whole internet all the time (without port knocker).

- **weakness**: If you use letmein to protect UDP ports, IP address spoofing can give some access for attackers after legitimate authentication of a user. With UDP IP address spoofing an attacker might be able to impersonate a legitimate user session after successful knocking.
  - **rationale**: This is a general property of UDP. The rationale is similar to that of NAT (see above). Letmein still massively reduces the attack surface by closing the port by default.

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
