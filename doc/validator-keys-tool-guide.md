# Validator Keys Tool Guide

This guide explains how to set up a validator so its public key does not have to
change if the rippled config and/or server are compromised.

A validator uses a public/private key pair. The validator is identified by the
public key. The private key should be tightly controlled. It is used to:

*   sign tokens authorizing a rippled server to run as the validator identified
    by this public key.
*   sign revocations indicating that the private key has been compromised and
    the validator public key should no longer be trusted.

Each new token invalidates all previous tokens for the validator public key.
The current token needs to be present in the rippled config file.

Servers that trust the validator will adapt automatically when the token
changes.

## Validator Keys

When first setting up a validator, use the `validator-keys` tool to generate
its key pair:

```
  $ validator-keys create_keys
```

Sample output:
```
  Validator keys stored in /home/ubuntu/.ripple/validator-keys.json
```

Keep the key file in a secure but recoverable location, such as an encrypted
USB flash drive. Do not modify its contents.

## Validator Token

After first creating the [validator keys](#validator-keys) or if the previous
token has been compromised, use the `validator-keys` tool to create a new
validator token:

```
  $ validator-keys create_token
```

Sample output:

```
  Update rippled.cfg file with these values:

  # validator public key: r4iKhWgGGUH1VYLXcnGExre1LJEoVUK2Jx

  [validator_token]
  ==
```

For a new validator, add the [validator_token] value to the rippled config file.
For a pre-existing validator, replace the old [validator_token] value with the
newly generated one. A valid config file may only contain one [validator_token]
value. After the config is updated, restart rippled.

There is a hard limit of 4,294,967,293 tokens that can be generated for a given
validator key pair.

## Key Revocation

If a validator private key is compromised, the key must be revoked permanently.
To revoke the validator key, use the `validator-keys` tool to generate a
revocation, which indicates to other servers that the key is no longer valid:

```
  $ validator-keys revoke_keys
```

Sample output:

```
  WARNING: This will revoke your validator keys!

  Update rippled.cfg file with these values and restart rippled:

  # validator public key: nHUtNnLVx7odrz5dnfb2xpIgbEeJPbzJWfdicSkGyVw1eE5GpjQr

  [validator_key_revocation]
  JP////9xIe0hvssbqmgzFH4/NDp1z|3ShkmCtFXuC5A0IUocppHopnASQN2MuMD1Puoyjvnr
  jQ2KJSO/2tsjRhjO6q0QQHppslQsKNSXWxjGQNIEa6nPisBOKlDDcJVZAMP4QcIyNCadzgM=
```

Add the `[validator_key_revocation]` value to this validator's config and
restart rippled. Rename the old key file and generate new [validator keys](#validator-keys) and
a corresponding [validator token](#validator-token).

## Signing

The `validator-keys` tool can be used to sign arbitrary data with the validator
key.

```
  $ validator-keys sign "your data to sign"
```

Sample output:

```
  B91B73536235BBA028D344B81DBCBECF19C1E0034AC21FB51C2351A138C9871162F3193D7C41A49FB7AABBC32BC2B116B1D5701807BE462D8800B5AEA4F0550D
```
