#!/usr/bin/env python3
import os
import glob
import re
import argparse

def combine_chunks(chunks_dir='processed_chunks', output_file='combined.rules'):
    """
    Combines all chunk*.rules files from chunks_dir into a single output file.
    Files are processed in ascending numeric order.
    """
    # Find all chunk*.rules files
    pattern = os.path.join(chunks_dir, 'chunk*.rules')
    chunk_files = glob.glob(pattern)
    
    if not chunk_files:
        print(f"[-] No chunk*.rules files found in '{chunks_dir}' directory.")
        return False
    
    # Sort files numerically by extracting the number from filename
    def extract_number(filepath):
        filename = os.path.basename(filepath)
        match = re.search(r'chunk(\d+)\.rules', filename)
        return int(match.group(1)) if match else 0
    
    chunk_files = sorted(chunk_files, key=extract_number)
    
    print(f"[*] Found {len(chunk_files)} chunk files to combine:")
    for f in chunk_files:
        print(f"    - {f}")
    
    # Combine all files
    total_lines = 0
    with open(output_file, 'w') as outfile:
        for chunk_file in chunk_files:
            with open(chunk_file, 'r') as infile:
                content = infile.read()
                outfile.write(content)
                # Ensure newline between chunks
                if content and not content.endswith('\n'):
                    outfile.write('\n')
                lines = content.count('\n') + (1 if content and not content.endswith('\n') else 0)
                total_lines += lines
                print(f"[+] Added {chunk_file} ({lines} lines)")
    
    print(f"\n[+] Successfully combined {len(chunk_files)} files into '{output_file}'")
    print(f"[+] Total lines: {total_lines}")
    return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Combine chunk*.rules files into a single output file.')
    parser.add_argument('chunks_dir', help='Directory containing chunk*.rules files')
    parser.add_argument('-o', '--output', default='combined.rules', help='Output file name (default: combined.rules)')
    
    args = parser.parse_args()
    
    combine_chunks(args.chunks_dir, args.output)
