# MPC Account Recovery (WIP)
The aim of this project is to offer NEAR users the opportunity to create and restore their accounts by utilizing OIDC protocol. By linking their NEAR account to Pagoda, Gmail, Github, or other authentication provider, they can then add a new Full Access key, which will be managed by the trusted network of servers. Should they lose all the keys they possess, they can reauthorize themselves, create a new key, and add it into their NEAR account using a transaction that will be signed by MPC servers through their recovery key. All the transaction cost will be covered by a relayer server and metatransactions.

## How the MPC system will work
- The system consists of N (4+) trusted nodes
- Each node holds a unique secret key
- Each action must be signed by N-1 node

Currently everything is signed by a single node with a single public key.

## External API

The recovery service is currently hosted at <https://mpc-recovery-7tk2cmmtcq-ue.a.run.app>.

### Create New Account

    URL: /new_account
    Request parameters: {
        near_account_id: String,
        oidc_token: String
    }
    Response: Ok / {"Err": String}

This creates an account with the name in `near_account_id`. If this name is already taken then this operation will fail with no action having been taken.

This service will send a `create_account` message to the relayer from `tmp_acount_creator.serhii.testnet` creating from the request field `near_account_id`. If this operation is successful the near.org relayer will make an allowance for the created account.


### Recover Account

    URL: /add_key
    Request parameters: {
        near_account_id: String,
        public_key: String,
        oidc_token: String
    }
    Response: "Ok" / {"Err": String}

## OIDC (OAuth 2.0) authentication

We are using OpenID Connect (OIDC) standard to authenticate users (built on top of OAuth 2.0).
Check OIDC standard docs [here](https://openid.net/specs/openid-connect-core-1_0.html#IDToken) and Google OIDC docs [here](https://developers.google.com/identity/protocols/oauth2/openid-connect)

### Client integration

There are several ways to get and use the ID token. The flow that we are using is called the "server" flow, you can find more info [here](https://developers.google.com/identity/openid-connect/openid-connect#authenticatingtheuser). The system will be able to process any token that is following the core OpenID Connect standard. In order to receive the ID token from OpenID provider you will need to include the `openid` scope value to the Authorization Request.

### Server integration

Internally, we are identifying users by their issuer id (iss) and their unique ID (sub) retrieved form the ID token and separated by a colon: `<issuer_iss>:<user_sub>`. It means that each recovery method (like GitHub and Google) is separated from one another even if they have the same email.

### Contribute

In order to build the project, you will need to have `protoc` installed and execute next commands:

```BASH
# init submodules
git submodule update --init --recursive
# build the Docker image
docker build . -t near/mpc-recovery
```

alternatively if you have [nix](https://nixos.org/) and [direnv](https://direnv.net/) installed, you can set up a development environment by running:

``` BASH
direnv allow
```

Run tests with:
```
cargo test -p mpc-recovery
cargo test -p mpc-recovery-integration-tests
```
If you are using docker you will need to re-build the Docker image each time you made a code change and want to run the integration tests.
