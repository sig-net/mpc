Usage:

To generate keys: first, on each node run `multiparty-signature-test init`. Then, on each signer node, run `multiparty-signature-test generate-key <ip:port>`, and on the leader node, run `multiparty-signature-test generate-key <threshold> <ip:port 1> ... <ip:port n-1>`. The signer nodes will listen for connections, and the leader node will connect.

To view derived key: on the leader node, run `multiparty-signature-test derive-key <account id> <email>`.

To generate a signature: choose t-1 signer nodes that will participate in addition to the leader node. On each of them, run `multiparty-signature-test sign <ip:port>`. On the leader node, run `multiparty-signature-test sign <account id> <email> <message> <ip:port 1> ... <ip:port n-1>`, but replace `<ip:port>` if nodes that don't participate with `-`.

To display information about node keys: `multiparty-signature-test info`.

Keys are stored in a file named `state` in the current working directory.
