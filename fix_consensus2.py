#!/usr/bin/env python3
"""
Update all advance method signatures and returns in consensus.rs
"""

import re

def fix_consensus():
    with open('/home/ubuntu/space/mpc1/chain-signatures/node/src/protocol/consensus.rs', 'r') as f:
        content = f.read()

    # Update impl signatures that don't have sign_rx yet
    # Pattern: async fn advance(\n        self,\n        ctx: &mut MpcSignProtocol,\n        _gov: &mut G,\n        contract_state: ProtocolState,\n    ) -> NodeState {
    content = re.sub(
        r'(async fn advance\(\s+self,\s+ctx: &mut MpcSignProtocol,\s+(?:_)?gov: &mut G,\s+contract_state: ProtocolState,)\s*\) -> NodeState \{',
        r'\1\n        sign_rx: mpsc::Receiver<IndexedSignRequest>,\n    ) -> (NodeState, mpsc::Receiver<IndexedSignRequest>) {',
        content
    )

    # Fix multi-line NodeState::XXX({ ... }) patterns at end of match arms or functions
    # These appear as standalone expressions that need wrapping
    # Pattern: NodeState::XXX(YYY {\n   fields\n})
    # Replace with: (NodeState::XXX(YYY {\n   fields\n}), sign_rx)

    # This is tricky because we need to match multi-line patterns
    # Let's handle specific common patterns:

    # Pattern 1: return NodeState::XXX(YYY {
    #                fields
    #            });
    content = re.sub(
        r'return (NodeState::\w+\(\w+\s*\{\s*\n(?:[^}]+\n)*\s*\}\));',
        r'return (\1, sign_rx);',
        content,
        flags=re.MULTILINE
    )

    # Pattern 2: NodeState::XXX(YYY {
    #                fields
    #            })
    # as last expression (no semicolon, followed by whitespace and })
    # This is hard to match precisely, so let's do it differently

    with open('/home/ubuntu/space/mpc1/chain-signatures/node/src/protocol/consensus.rs', 'w') as f:
        f.write(content)

    print("Updated consensus.rs signatures and some returns")

if __name__ == '__main__':
    fix_consensus()
