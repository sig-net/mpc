# Iteracting with contract using NEAR CLI
All data is fake and used for example purposes
It's necessary to update script after contract API changes
## User contract API

near call dev.sig-net.testnet sign '{"request":{"key_version":0,"path":"test","payload":[12,1,2,0,4,5,6,8,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,44]}}' --accountId caller.testnet --gas 300000000000000 --deposit 1

near view dev.sig-net.testnet public_key

near view dev.sig-net.testnet derived_public_key {"path":"test","predecessor":"caller.testnet"}

near view dev.sig-net.testnet latest_key_version

near view dev.sig-net.testnet experimental_signature_deposit


## Node API

near call dev.sig-net.testnet respond '{"sign_id":{"request_id":[151,136,167,147,23,20,220,213,86,31,230,217,37,206,97,80,223,72,36,70,44,77,91,179,109,37,13,51,45,169,145,45]},"signature":{"big_r":"02EC7FA686BB430A4B700BDA07F2E07D6333D9E33AEEF270334EB2D00D0A6FEC6C","recovery_id":0,"s":"20F90C540EE00133C911EA2A9ADE2ABBCC7AD820687F75E011DFEEC94DB10CD6"}}' --accountId caller.testnet --gas 300000000000000

near call dev.sig-net.testnet join '{"cipher_pk":[191,189,17,200,98,182,124,6,250,135,105,237,235,209,59,10,253,255,91,17,160,20,87,155,10,174,253,188,42,55,98,104],"sign_pk":"ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae","url":"http://localhost:3030"}' --accountId caller.testnet --gas 300000000000000

near call dev.sig-net.testnet vote_join '{"candidate":"caller.testnet"}' --accountId caller.testnet --gas 300000000000000

near call dev.sig-net.testnet vote_leave '{"kick":"caller.testnet"}' --accountId caller.testnet --gas 300000000000000

near call dev.sig-net.testnet vote_pk '{"public_key": ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae}' --accountId caller.testnet --gas 300000000000000

near call dev.sig-net.testnet vote_reshared '{"epoch": 1}' --accountId caller.testnet --gas 300000000000000

near call dev.sig-net.testnet propose_update --base64 "AAHgkwQAAAAAAADdbQAAAAAACgAAAEABAAAAEAAAAAAAAcAnCQAAAAAAAAAAAAAIAAAAAIAAyK8AAAAAAAAAAAAAyK8AAAAAAABADQMAAAAAAABcJgUAAAAAAAAAAAAAAAAAAAAA" --accountId caller.testnet --gas 300000000000000

near call dev.sig-net.testnet vote_update '{"id": 0}' --accountId caller.testnet --gas 300000000000000


## Contract developer helper API

near call dev.sig-net.testnet init '{"candidates":{"candidates":{"alice.near":{"account_id":"alice.near","cipher_pk":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"sign_pk":"ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae","url":"127.0.0.1"},"bob.near":{"account_id":"bob.near","cipher_pk":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"sign_pk":"ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae","url":"127.0.0.1"},"caesar.near":{"account_id":"caesar.near","cipher_pk":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"sign_pk":"ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae","url":"127.0.0.1"}}},"threshold":1}' --accountId caller.testnet --gas 300000000000000

near call dev.sig-net.testnet init_running '{"epoch":0,"participants":{"account_to_participant_id":{"alice.near":0,"bob.near":1,"caesar.near":2},"next_id":3,"participants":{"alice.near":{"account_id":"alice.near","cipher_pk":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"sign_pk":"ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae","url":"127.0.0.1"},"bob.near":{"account_id":"bob.near","cipher_pk":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"sign_pk":"ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae","url":"127.0.0.1"},"caesar.near":{"account_id":"caesar.near","cipher_pk":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"sign_pk":"ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae","url":"127.0.0.1"}}},"public_key":"ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae","threshold":2}' --accountId caller.testnet --gas 300000000000000

near view dev.sig-net.testnet migrate

near view dev.sig-net.testnet state

near view dev.sig-net.testnet config

near view dev.sig-net.testnet version

