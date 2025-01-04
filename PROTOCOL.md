# letmein - Network message format

All messages transmitted between the server (`letmeind`) and the client (`letmein`) applications have the same format and the same size (56 bytes):

| Byte offset | Size in bytes | Field name |
| ----------- | ------------- | ---------- |
| 0           | 4             | MAGIC      |
| 4           | 4             | OPERATION  |
| 8           | 4             | USER       |
| 12          | 4             | RESOURCE   |
| 16          | 8             | SALT       |
| 24          | 32            | AUTH       |

## Field: MAGIC

The magic code is always `0x3B1BB719` (hex) encoded as big-endian for all message types.
There is no special meaning to this value.
It has been randomly chosen.

## Field: OPERATION

| Operation ID | Operation Name |
| ------------ | -------------- |
| 0            | KNOCK          |
| 1            | CHALLENGE      |
| 2            | RESPONSE       |
| 3            | COMEIN         |
| 4            | GOAWAY         |

This field defines the message type.
Only certain types of operations are allowed during different states of the communication.
See [Typical communication flow](PROTOCOL.md#typical-communication-flow) below.

The `OPERATION` field is encoded as big-endian 32-bit.

## Field: USER

The user is the selected user identifier from the
[KEYS](CONFIGURATION.md#keys)
section of the configuration file.
It identifies the user and the corresponding cryptographic key to be used for encryption.

The `USER` field is encoded as big-endian 32-bit.

## Field: RESOURCE

the resource is the selected resource identifier from the
[RESOURCES](CONFIGURATION.md#resources)
section of the configuration file.
It identifies the resource (port) that is supposed to get knocked open.

The `RESOURCE` field is encoded as big-endian 32-bit.

## Field: SALT

The salt is 8 random bytes
[unique to every message](https://en.wikipedia.org/wiki/Cryptographic_nonce).
The salt is generated with a secure
[CPRNG](https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator).
The salt is never reused.
It is always freshly generated for each message.

## Field: AUTH

The auth field has different meanings depending on the `OPERATION`.
See the [Cryptography](PROTOCOL.md#cryptography) section below for a detailed description about how the `AUTH` field is generated and validated.

# Typical communication flow

Successful knocking:

| Client      | Server       | Server Firewall      |
| ----------: | :----------- | -------------------- |
| KNOCK ->    |              |                      |
|             | <- CHALLENGE |                      |
| RESPONSE -> |              |                      |
|             | <- COMEIN    | Firewall port opened |

If something goes wrong the server can send the `GOAWAY` message to the client at any time.
Whether and when that actually happens depends on the
[error policy configuration](CONFIGURATION.md#control-error-policy).

# Cryptography

## Message: KNOCK

TODO

## Message: CHALLENGE

TODO

## Message: RESPONSE

TODO

## Message: COMEIN

The `COMEIN` message is not cryptographically secured.
The `SALT` and `AUTH` fields of this message are ignored.

## Message: GOAWAY

The `GOAWAY` message is not cryptographically secured.
The `SALT` and `AUTH` fields of this message are ignored.
