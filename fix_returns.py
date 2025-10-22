#!/usr/bin/env python3
"""
Fix all remaining returns in consensus.rs to wrap NodeState in tuples with sign_rx
"""

import re

def fix_all_returns():
    with open('/home/ubuntu/space/mpc1/chain-signatures/node/src/protocol/consensus.rs', 'r') as f:
        lines = f.readlines()

    result = []
    i = 0
    in_advance_function = False
    brace_depth = 0

    while i < len(lines):
        line = lines[i]

        # Track if we're inside an advance function
        if 'async fn advance' in line:
            in_advance_function = True
            brace_depth = 0

        if in_advance_function:
            # Track braces
            brace_depth += line.count('{') - line.count('}')

            # If braces are balanced, we left the function
            if brace_depth <= 0 and i > 0:
                in_advance_function = False

        # Only process lines inside advance functions
        if in_advance_function:
            # Pattern 1: Simple NodeState::XXX(self) or NodeState::XXX(YYY {...})
            # at end of line (as expression, not in return statement)
            if re.match(r'^\s+(NodeState::\w+\(.+\))$', line):
                line = re.sub(r'^(\s+)(NodeState::\w+\(.+\))$', r'\1(\2, sign_rx)', line)

            # Pattern 2: Already has return keyword but not wrapped
            # return NodeState::XXX(...); -> return (NodeState::XXX(...), sign_rx);
            if 'return' in line and 'NodeState::' in line and not line.strip().startswith('//'):
                if 'return (' not in line or ', sign_rx)' not in line:
                    line = re.sub(
                        r'(\s+)return\s+(NodeState::\w+\([^)]+\));',
                        r'\1return (\2, sign_rx);',
                        line
                    )

        result.append(line)
        i += 1

    with open('/home/ubuntu/space/mpc1/chain-signatures/node/src/protocol/consensus.rs', 'w') as f:
        f.writelines(result)

    print("Fixed returns")

if __name__ == '__main__':
    fix_all_returns()
