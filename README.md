# MPC Account Recovery (WIP)
The aim of this project is to offer NEAR users the opportunity to restore their accounts by utilizing OAuth authorization. By linking their NEAR account to Gmail, Github, or other authentication provider, they can then add a new Full Access key, which will be managed by the trusted network of servers. Should they lose all the keys they possess, they can reauthorize themselves, create a new key, and add it into their NEAR account using a transaction that will be signed by MPC servers through their recovery key.

## Adding a recovery method
1. The user is getting OAuth access token (AT) from their authentication provider
2. The user is signing this AT with their NEAR private key
3. The user is sending the created payload to the multi-party computation system (MPC, or just "server").
4. Server checks the AT
5. Server fetches the list of user keys and checks the signature
6. If all the checks were successful, server adds recovery method to it's database and generates a new key using Key Derivation technique
7. User gets the public key (PK) from the server and adds it as a Full Access key to their NEAR account.


## Using previously added recovery method
1. The user is getting OAuth access token from it's authentication provider
2. The user generates a new key they want to add to their NEAR account
3. The user sends the AT alongside with PK to the server
4. Server checks the AT
5. Server adds the provided PK to the users account

## How the MPC system works
- The system consists of N (4+) trusted nodes
- Each node holds a unique secret key
- Each action must be signed by N-1 node

## External API
Endpoint 1: Add Recovery Method

    URL: /add_recovery_method
    Request parameters: access_token, signature, accountId
    Response: recovery_public_key

Endpoint 2: Recover Account

    URL: /recover_account
    Request parameters: access_token, public_key
    Response: status

## OIDC (OAuth 2.0) authentication
We are using OpenID Connect (OIDC) standard to authenticate users (built on top of OAuth 2.0).
Check OIDC standard docs [here](https://openid.net/specs/openid-connect-core-1_0.html#IDToken) and Google OIDC docs [here](https://developers.google.com/identity/protocols/oauth2/openid-connect)

### Client integration
There are several ways to get and use the ID token. The flow that we are using is called the "server" flow, you can find more info [here](https://developers.google.com/identity/openid-connect/openid-connect#authenticatingtheuser). The system will be able to process any token that is following the core OpenID Connect standard. In order to recieve the ID token from OpenID provider you will need to include the `openid` scope value to the Authorization Request.

### Server integration
Internally, we are identifiying users by their issuer id (iss) and their unique ID (sub) retrieved form the ID token and separated by a colon: `<issuer_iss>:<user_sub>`. It means that each recovery method (like GitHub abd Google) is separated from one another even if they have the same email.

### Contribute

In order to build the project, you will need to have `protoc` installed and execute next commands:

```BASH
# init submodules
git submodule update --init --recursive
# build the Docker image
docker build . -t near/mpc-recovery
```

Run tests with:
```
cargo test -p mpc-recovery
cargo test -p mpc-recovery-integration-tests
```
You will need to re-build the Docker image each time you made a code change and want to run the integration tests.