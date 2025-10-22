#!/usr/bin/env python3
import re

with open('chain-signatures/node/src/protocol/consensus.rs', 'r') as f:
    content = f.read()

# 1. Fix all impl signatures - remove sign_rx parameter and tuple return
content = re.sub(
    r'async fn advance\(\s*self,\s*ctx: &mut MpcSignProtocol,\s*gov: &mut G,\s*contract_state: ProtocolState,\s*sign_rx: mpsc::Receiver<IndexedSignRequest>,\s*\) -> \(NodeState, mpsc::Receiver<IndexedSignRequest>\)',
    'async fn advance(\n        self,\n        ctx: &mut MpcSignProtocol,\n        gov: &mut G,\n        contract_state: ProtocolState,\n    ) -> NodeState',
    content
)

# 2. Fix all JoiningState constructions - add sign_rx: None or self.sign_rx
# Pattern: JoiningState { participants: ..., public_key: ... }
# Replace with: JoiningState { participants: ..., public_key: ..., sign_rx: None }
content = re.sub(
    r'(NodeState::Joining\(JoiningState\s*\{\s*participants:\s*[^,}]+,\s*public_key:\s*[^,}]+)(,\s*sign_rx:\s*[^}]+)?\s*\}\)',
    r'\1, sign_rx: None })',
    content
)

# 3. Fix all GeneratingState constructions - add sign_rx field
content = re.sub(
    r'(NodeState::Generating\(GeneratingState\s*\{[^}]*failed_store:\s*[^,}]+)(,\s*sign_rx:\s*[^}]+)?\s*\}\)',
    r'\1, sign_rx: None })',
    content
)

# 4. Fix return statements - remove tuple wrapping and sign_rx parameter
# Pattern: return (NodeState::..., sign_rx); -> return NodeState::...;
content = re.sub(
    r'return \((NodeState::[^,)]+)\s*,\s*sign_rx\);',
    r'return \1;',
    content
)

# 5. Fix simple returns without explicit return keyword
# Pattern: (NodeState::XXX(...), sign_rx) -> NodeState::XXX(...)
content = re.sub(
    r'\(NodeState::([A-Za-z]+)\(([^)]+)\)\s*,\s*sign_rx\)',
    r'NodeState::\1(\2)',
    content
)

with open('chain-signatures/node/src/protocol/consensus.rs', 'w') as f:
    f.write(content)

print("Fixed consensus.rs - removed sign_rx parameter and tuple returns")
