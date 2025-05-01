#!/usr/bin/env python3

import re
import sys

def transform_disassembly(lines):
    """
    Transform llvm-objdump disassembly to a Go byte array literal.
    Written by Claude.

    This function:
    1. Removes offset prefixes (like "15e5b:")
    2. Adds "0x" prefix to each byte and comma separators
    3. Comments out the disassembly parts with "//"

    Args:
        lines: A list of input lines to transform

    Returns:
        A list of transformed lines
    """
    result = []

    for line in lines:
        # Skip empty lines
        if not line.strip():
            continue

        # Extract the parts using regex
        # Match the address prefix, then bytes, then the assembly instruction
        match = re.match(r'^\s*[0-9a-f]+:\s+([0-9a-f\s]+)(.+)$', line)
        if match:
            # Get the machine code bytes
            bytes_str = match.group(1).strip()
            # Get the assembly instruction
            asm_instr = match.group(2).strip()

            # Split the bytes and add 0x prefix and commas
            bytes_list = [f"0x{b}" for b in bytes_str.split()]
            formatted_bytes = ", ".join(bytes_list) + ","

            # Pad with spaces to align comments
            pad_length = max(40 - len(formatted_bytes), 1)
            padding = " " * pad_length

            # Create the Go byte array line with commented assembly
            result.append(f"{formatted_bytes}{padding}// {asm_instr}")
        else:
            # If the line doesn't match our expected format, keep it as a comment
            result.append(f"// {line.strip()}")

    return result

def main():
    # Read from stdin
    lines = sys.stdin.readlines()

    # Transform the lines
    transformed_lines = transform_disassembly(lines)

    # Write to stdout
    sys.stdout.write("\n".join(transformed_lines))
    sys.stdout.write("\n")  # Add a final newline

if __name__ == "__main__":
    main()