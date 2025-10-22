#!/usr/bin/env python3
import re

with open('chain-signatures/node/src/protocol/consensus.rs', 'r') as f:
    content = f.read()

# 1. Fix all impl signatures - remove sign_rx parameter and tuple return
content = re.sub(
    r'(async fn advance\(\s*self,\s*ctx: &mut MpcSignProtocol,\s*gov: &mut G,\s*contract_state: ProtocolState),\s*sign_rx: mpsc::Receiver<IndexedSignRequest>,\s*\) -> \(NodeState, mpsc::Receiver<IndexedSignRequest>\)',
    r'\1\n    ) -> NodeState',
    content
)

# 2. Fix JoiningState constructions
# Pattern: JoiningState {\n            participants: xxx,\n            public_key: xxx,\n        }
content = re.sub(
    r'(JoiningState\s*\{\s*participants:\s*[^,]+,\s*public_key:\s*[^,}]+)(\s*\})',
    r'\1,\n                sign_rx: None\2',
    content
)

# 3. Fix GeneratingState constructions - add sign_rx: None before closing }
content = re.sub(
    r'(GeneratingState\s*\{[^}]*failed_store:\s*Default::default\(\))(\s*\})',
    r'\1,\n                sign_rx: None\2',
    content
)

# 4. Fix StartedState with sign_rx: None
content = re.sub(
    r'(StartedState\s*\{\s*persistent_node_data)(\s*\})',
    r'\1,\n                sign_rx: None\2',
    content
)

with open('chain-signatures/node/src/protocol/consensus.rs', 'w') as f:
    f.write(content)

print("Fixed consensus.rs")
