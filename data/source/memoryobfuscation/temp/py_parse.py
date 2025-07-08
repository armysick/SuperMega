import re

# Input file with your big array (e.g. sidecar_bin.c or .txt)
input_file = "wtv"

# How many bytes per chunk
chunk_size = 4000

# Read file content
with open(input_file, "r") as f:
    content = f.read()

# Extract all hex byte values (like 0xe8, 0xc0, etc.)
bytes_hex = re.findall(r"0x[0-9a-fA-F]{2}", content)

# Convert hex strings to integers
bytes_int = [int(b, 16) for b in bytes_hex]

# Split into chunks of chunk_size
chunks = [bytes_int[i:i+chunk_size] for i in range(0, len(bytes_int), chunk_size)]

# Write chunks as separate arrays to files
for idx, chunk in enumerate(chunks):
    array_name = f"sidecar_bin_part_{idx}"
    with open(f"{array_name}.h", "w") as out:
        out.write(f"unsigned char {array_name}[] = {{\n")
        for i, b in enumerate(chunk):
            out.write(f"0x{b:02x}, ")
            if (i + 1) % 12 == 0:
                out.write("\n")
        out.write("\n};\n")
        out.write(f"unsigned int {array_name}_len = {len(chunk)};\n")

print(f"Split into {len(chunks)} files, each up to {chunk_size} bytes.")

