#!/usr/bin/env python3
"""
Script to update consensus.rs to pass sign_rx through all state transitions.
"""

import re

def update_file():
    with open('/home/ubuntu/space/mpc1/chain-signatures/node/src/protocol/consensus.rs', 'r') as f:
        content = f.read()

    # Pattern to match simple return statements like "NodeState::XXX(self)" or "NodeState::XXX(YYY {...})"
    # We need to replace them with "(NodeState::XXX(...), sign_rx)"

    # First, update all simple returns of form "return NodeState::XXX(...)"
    content = re.sub(
        r'(\s+)return (NodeState::\w+\([^;]+\));',
        r'\1return (\2, sign_rx);',
        content
    )

    # Update all end-of-function returns of form "NodeState::XXX(...)"
    # that are NOT already wrapped in parentheses
    content = re.sub(
        r'(\s+)(NodeState::\w+\([^)]+\))(\s*})',
        r'\1(\2, sign_rx)\3',
        content
    )

    with open('/home/ubuntu/space/mpc1/chain-signatures/node/src/protocol/consensus.rs', 'w') as f:
        f.write(content)

if __name__ == '__main__':
    update_file()
    print("Updated consensus.rs")
