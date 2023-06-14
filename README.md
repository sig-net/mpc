# MPC Account Recovery (WIP)
The aim of this project is to offer NEAR users the opportunity to create and restore their accounts by utilizing OIDC protocol. By linking their NEAR account to Pagoda, Gmail, Github, or other authentication provider, they can then add a new Full Access key, which will be managed by the trusted network of servers. Should they lose all the keys they possess, they can reauthorize themselves, create a new key, and add it into their NEAR account using a transaction that will be signed by MPC servers through their recovery key. All the transaction cost will be covered by a relayer server and metatransactions.

## How the MPC system will work
- The system consists of N (4+) trusted nodes
- Each node holds a unique secret key
- Each action must be signed by N-1 node

Currently everything is signed by a single node with a single private key.

## External API

The recovery service is currently hosted at <https://mpc-recovery-7tk2cmmtcq-ue.a.run.app>.

All byte arguments are sent as a hex string.

### Claim OIDC ownership

    URL: /claim_id_token
    Request parameters: {
        id_token_hash: [u8; 32],
        public_key: String,
        signature: [u8; 64],
    }
    Response: Ok {
        "mpc_signature": String,
        "recovery_public_key": Option<String>,
        "account_id": Option<String>,
    } / {"Err": String}

Before transmitting your IODC Id Token to the recovery service you must first claim the ownership of the token. This prevents a rogue node from taking your token and using it to sign another request.

The signature you send must be an Ed22519 signature of the hash:

    SALT = 3177899144
    sha256.hash(Borsh.serialize<u32>(SALT + 0) ++ Borsh.serialize<[u8]>(id_token_hash))

signed with your on device public key.

The constant 3177899144 is a random number between 2^31 and 2^32 which as described [here](https://github.com/gutsyphilip/NEPs/blob/8b0b05c3727f0a90b70c6f88791152f54bf5b77f/neps/nep-0413.md#example) prevents collisions with legitimate on chain transactions.

If you successfully claim the token you will receive a signature in return of:

    sha256.hash(Borsh.serialize<u32>(SALT + 1) ++ Borsh.serialize<[u8]>(signature))

This will be signed by the nodes combined Ed22519 signature. PK that you will use to check it should be hard coded in your validation code NOT fetched from the nodes themselves.

Current MPC PK is:
```
TODO: add MPC PK
```

If user has already used this token to claim an account, then the response will contain the account id and the recovery public key.

If this repeatedly fails, you should discard your oidc token and regenerate.

### Create New Account

    URL: /new_account
    Request parameters: {
        near_account_id: String,
        oidc_token: String,
        public_key: String,
        signature: String,
    }
    Response:
    Ok {
        user_public_key: String,
        user_recovery_public_key: String,
        near_account_id: String,
    } /
    Err {
        msg: String
    }

This creates an account with account Id provided in `near_account_id`. If this name is already taken then this operation will fail with no action having been taken.

This service will send a `create_account` transaction to the relayer signed by `account_creator.near` account. If this operation is successful relayer will make an allowance for the created account.

Newly created NEAR account will have two full access keys. One that was provided by the user, and the recovery one that is controlled by the MPC system.

MPC Service will disallow creating account with ID Tokes that were not claimed first. It is expected, that PK that client wants to use for the account creation is the same as the one that was used to claim the ID Token.

The signature field is a signature of:

    sha256.hash(Borsh.serialize<u32>(SALT + 2) ++ Borsh.serialize({
        near_account_id: Option<String>,
        oidc_token: String,
        public_key: String,
    }))

signed by the key you used to claim the oidc token. This does not have to be the same as the key in the public key field.

### Recover Account

    URL: /sign
    Request parameters: {
        transaction: String,
        oidc_token: String
        public_key: String,
        signature: String,
    }
    Response:
    Ok {
        // TODO: what usefull info should we return?
    } /
    Err{
        msg: String
    }

The signature field is a signature of:

    sha256.hash(Borsh.serialize<u32>(SALT + 3) ++ Borsh.serialize({
        transaction: String,
        oidc_token: String,
        public_key: String,
    }))

signed by the key you used to claim the oidc token.

## OIDC (OAuth 2.0) authentication

We are using OpenID Connect (OIDC) standard to authenticate users (built on top of OAuth 2.0).
Check OIDC standard docs [here](https://openid.net/specs/openid-connect-core-1_0.html#IDToken) and Google OIDC docs [here](https://developers.google.com/identity/protocols/oauth2/openid-connect)

### Client integration

There are several ways to get and use the ID token. The flow that we are using is called the "server" flow, you can find more info [here](https://developers.google.com/identity/openid-connect/openid-connect#authenticatingtheuser). The system will be able to process any token that is following the core OpenID Connect standard. In order to receive the ID token from OpenID provider you will need to include the `openid` scope value to the Authorization Request.

### Server integration

Internally, we are identifying users by their issuer id (iss) and their unique ID (sub) retrieved form the ID token and separated by a colon: `<issuer_iss>:<user_sub>`. It means that each recovery method (like GitHub and Google) is separated from one another even if they have the same email.

### Contribute

In order to build the project, you will need to have `protoc` and `gmp` installed. Refer to your system's package manager on how to do this.

If you have [nix](https://nixos.org/) and [direnv](https://direnv.net/) installed, you can set up a development environment by running:

```BASH
direnv allow
```

Run unit tests with:
```BASH
cargo test -p mpc-recovery
```
