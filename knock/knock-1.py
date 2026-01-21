import itertools
import argparse
import ast

def parse_items(value):
    """
    Convert CLI input to a list.
    Supports:
    - List literals: [1,2,3]
    - Range syntax: range(start,stop[,step])
    """
    value = value.strip()
    
    if value.startswith("range(") and value.endswith(")"):
        # Extract numbers inside parentheses
        numbers = value[6:-1]
        parts = [int(x.strip()) for x in numbers.split(",")]
        return list(range(*parts))
    
    # Otherwise, parse as Python literal
    return list(ast.literal_eval(value))

# Setup argparse
parser = argparse.ArgumentParser(description="Generate permutations")

parser.add_argument(
    "--items",
    type=parse_items,
    required=True,
    help='List like [1,2,3] or range(start,stop[,step])'
)

parser.add_argument(
    "--length",
    type=int,
    required=True,
    help="Length of each permutation"
)

args = parser.parse_args()

# Generate permutations
perms = []
for p in itertools.permutations(args.items, args.length):
    perms.append(p)
    print(p)
print(perms)
