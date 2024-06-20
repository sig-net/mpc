module Main where

import Development.Shake
import Development.Shake.Command
import Development.Shake.FilePath
import Development.Shake.Util

main :: IO ()
main = putStrLn "Hello"

data Package = Package {_manifest_path :: FilePath, _package :: String}

cargo :: (CmdResult r) => String -> [String] -> [String] -> Package -> Action r
cargo cargo_cmd cargo_args binary_args package =
  command [AutoDeps] "cargo" $
    cargo_args
      ++ [cargo_cmd, "--package", _package package, "--manifest_path", _manifest_path package]
      ++ "--"
      : binary_args

-- These can all probably be extracted automatically using
-- find -name "Cargo.toml" | xargs -I {} sh -c 'echo --package $(cargo metadata --no-deps --format-version=1 --manifest-path {} | jq -r ".packages[].name") --manifest-path {}'
-- but it seems a little brittle
packages :: [Package]
packages =
  [ contract,
    cryptoShared,
    mpcKeys,
    node,
    chainSignauturesTest,
    fastauthTest,
    loadTests,
    oidcProviderTest,
    fastauth
  ]

contract, cryptoShared, mpcKeys, node, chainSignauturesTest, fastauthTest, loadTests, oidcProviderTest, fastauth :: Package
(contract, cryptoShared, mpcKeys, node) = (p "mpc-contract", p "crypto-shared", p "mpc-keys", p "mpc-recovery-node")
  where
    p _package = Package {
      _package,
      _manifest_path = "integration-tests/chain-signatures/Cargo.toml"}
chainSignauturesTest =
  Package {_package = "integration-tests-chain-signatures",
           _manifest_path = "integration-tests/chain-signatures/Cargo.toml"}
fastauthTest =
  Package {_package = "integration-tests-fastauth",
           _manifest_path = "integration-tests/fastauth/Cargo.toml"}
loadTests =
  Package {_package = "load-tests",
           _manifest_path = "load-tests/Cargo.toml"}
oidcProviderTest =
  Package {_package = "test-oidc-provider",
           _manifest_path = "test-oidc-provider/Cargo.toml"}
fastauth =
  Package {_package = "mpc-recovery",
           _manifest_path = "mpc-recovery/Cargo.toml"}

clippy, fmt, check :: CmdResult r => Package -> Action r
clippy = cargo "clippy" ["--tests"] ["-Dclippy:all"]
fmt = cargo "fmt" ["--tests"] ["--check"]
check = cargo "check" ["--tests"] []
