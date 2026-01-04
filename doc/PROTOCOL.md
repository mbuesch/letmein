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
| 5            | REVOKE         |

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

A communication flow always starts with a `KNOCK` message from the client to the server.

A `CHALLENGE` from the server can only follow a `KNOCK` from the client.

A `RESPONSE` from the client can only follow a `CHALLENGE` from the server.

A `COMEIN` from the server can only follow a `RESPONSE` from the client.

A successful knocking always ends with a `COMEIN` message from the server to the client.

If something goes wrong the server can send the `GOAWAY` message to the client at any time.
Whether and when that actually happens depends on the
[error policy configuration](CONFIGURATION.md#control-error-policy).

All other message flow combinations are invalid and shall result in an immediate stop of the communication and authentication.
Invalid combinations may or may not trigger a `GOAWAY`, depending on the error policy configuration.

The `USER` and `RESOURCE` values in all messages shall always be equal to what the client requested in the first `KNOCK` message.

# Cryptography

## Message: KNOCK

The `OPERATION` field of this message shall be `KNOCK`.

The `USER` and `RESOURCE` fields of this message shall be what the user requested.

The `SALT` field in this message shall be a cryptographically secure nonce.

Use a 32 byte long all-zeros `CHALLENGE_TOKEN`,
[generate a new AUTH token](PROTOCOL.md#generate-auth-token)
and use the result as the `AUTH` field of this `KNOCK` message.

The server must
[validate the received AUTH token](PROTOCOL.md#validate-auth-token)
of this `KNOCK` message before continuing with the communication flow.
It is valid but not mandatory to send a `GOAWAY` message from server to client, if the validation failed.
The communication must not continue beyond that, if validation failed.

## Message: CHALLENGE

The `OPERATION` field of this message shall be `CHALLENGE`.

The `USER` and `RESOURCE` fields of this message are set to the same values used in the `KNOCK` message.

The `SALT` field of this message is ignored.

The `AUTH` field in this message shall be a securely generated random 32 byte long nonce.
This is the `CHALLENGE_TOKEN`.

## Message: RESPONSE

The `OPERATION` field of this message shall be `RESPONSE`.

The `USER` and `RESOURCE` fields of this message are set to the same values used in the `KNOCK` message.

The `SALT` field in this message shall be a cryptographically secure nonce.

Use the `AUTH` field of the `CHALLENGE` message that we are answering to as the `CHALLENGE_TOKEN`.
Then
[generate a new AUTH token](PROTOCOL.md#generate-auth-token)
and use the result as the `AUTH` field of this `RESPONSE` message.

The server must
[validate the received AUTH token](PROTOCOL.md#validate-auth-token)
of this `RESPONSE` message before continuing with the communication flow.
It is valid but not mandatory to send a `GOAWAY` message from server to client, if the validation failed.
The communication must not continue beyond that, if validation failed.

## Message: COMEIN

The `COMEIN` message is not cryptographically secured.

The `OPERATION` field of this message shall be `COMEIN`.

The `USER` and `RESOURCE` fields of this message are set to the same values used in the `KNOCK` message.

The `SALT` and `AUTH` fields of this message are ignored.

## Message: GOAWAY

The `GOAWAY` message is not cryptographically secured.

The `OPERATION` field of this message shall be `GOAWAY`.

The `USER` and `RESOURCE` fields of this message are always set to the same values used in the `KNOCK` message.

The `SALT` and `AUTH` fields of this message are ignored.

## Message: REVOKE

The `OPERATION` field of this message shall be `REVOKE`.

All other fields of the message shall be equal these of the `KNOCK` message type.

The communication flow of a `REVOKE` communication is equal to that of a `KNOCK` communication.

But the server reacts to `REVOKE` by closing/removing the resource instead of opening/adding it.

## Generate AUTH token

The inputs for generating an `AUTH` token are:

- The pre-shared `KEY` (length 32 bytes).
- The `CHALLENGE_TOKEN` (length 32 bytes).
- The `OPERATION` field of the message that this `AUTH` token is generated for.
- The `USER` field of the message that this `AUTH` token is generated for.
- The `RESOURCE` field of the message that this `AUTH` token is generated for.
- The `SALT` field of the message that this `AUTH` token is generated for.

The output is the `AUTH` token with length 32 bytes.

Compute the `AUTH` token as follows:

```
AUTH := HMAC_SHA3_256(KEY)(
    message.OPERATION ||
    message.USER      ||
    message.RESOURCE  ||
    message.SALT      ||
    CHALLENGE_TOKEN
)
```

This is the core cryptographic algorithm of letmein.

It uses
[HMAC](https://en.wikipedia.org/wiki/HMAC)
together with a
[SHA3-256](https://en.wikipedia.org/wiki/SHA-3)
algorithm.

All integer elements shall be serialized in 32-bit big-endian byte order before passing them to HMAC function.
The `||`-operator in the algorithm description above is a concatenation of the serialized bytes.

## Validate AUTH token

Validation always only happens on the server side.

Generate the [EXPECTED_AUTH token](PROTOCOL.md#generate-auth-token) for the received message using the expected `CHALLENGE_TOKEN`.
For a `KNOCK` message the expected `CHALLENGE_TOKEN` is 32 bytes of zeros.
For a `RESPONSE` message the expected `CHALLENGE_TOKEN` is the `AUTH` field of the `CHALLENGE` message that the server sent to the client.

Compare the `EXPECTED_AUTH` token to the actual `AUTH` token of the `RESPONSE` message using a Constant Time Comparison Function.
The result of the validation is Ok, if the tokens are equal.
