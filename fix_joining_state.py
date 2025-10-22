#!/usr/bin/env python3
import re

with open('chain-signatures/node/src/protocol/consensus.rs', 'r') as f:
    lines = f.readlines()

output = []
i = 0
while i < len(lines):
    line = lines[i]

    # Check if this line contains JoiningState construction
    if 'NodeState::Joining(JoiningState {' in line or 'JoiningState {' in line:
        # Collect the full struct construction
        struct_lines = [line]
        brace_count = line.count('{') - line.count('}')
        j = i + 1

        while j < len(lines) and brace_count > 0:
            struct_lines.append(lines[j])
            brace_count += lines[j].count('{') - lines[j].count('}')
            j += 1

        # Check if sign_rx is already in the struct
        full_struct = ''.join(struct_lines)
        if 'sign_rx:' not in full_struct:
            # Need to add sign_rx field
            # Find the last line before the closing braces
            last_field_idx = len(struct_lines) - 1
            for k in range(len(struct_lines) - 1, -1, -1):
                if 'public_key:' in struct_lines[k]:
                    last_field_idx = k
                    break

            # Add sign_rx: None after public_key
            if ',' in struct_lines[last_field_idx]:
                # Already has comma, add new line
                indent = len(struct_lines[last_field_idx]) - len(struct_lines[last_field_idx].lstrip())
                output.extend(struct_lines[:last_field_idx + 1])
                output.append(' ' * indent + 'sign_rx: None,\n')
                output.extend(struct_lines[last_field_idx + 1:])
            else:
                # Need to add comma first
                struct_lines[last_field_idx] = struct_lines[last_field_idx].rstrip() + ',\n'
                indent = len(struct_lines[last_field_idx]) - len(struct_lines[last_field_idx].lstrip())
                output.extend(struct_lines[:last_field_idx + 1])
                output.append(' ' * indent + 'sign_rx: None,\n')
                output.extend(struct_lines[last_field_idx + 1:])
        else:
            output.extend(struct_lines)

        i = j
    else:
        output.append(line)
        i += 1

with open('chain-signatures/node/src/protocol/consensus.rs', 'w') as f:
    f.writelines(output)

print("Fixed all JoiningState constructions")
