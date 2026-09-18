import sys
import tokenize
import io
import os

def minify_python(input_path):
    base, ext = os.path.splitext(input_path)
    output_path = f"{base}_output{ext}"

    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            source = f.read()

        tokens = tokenize.generate_tokens(io.StringIO(source).readline)
        result = []
        
        # We use these to track if the previous token was a newline
        # to prevent double-spacing.
        prev_toktype = None

        for toktype, tokval, start, end, line in tokens:
            # 1. Remove Comments
            if toktype == tokenize.COMMENT:
                continue
            
            # 2. Remove Non-logical newlines (extra empty lines)
            if toktype == tokenize.NL:
                continue

            # 3. Remove Docstrings
            if toktype == tokenize.STRING:
                # If the string is the start of a line/statement (like a docstring)
                # we skip it. Standard strings inside assignments are kept.
                if prev_toktype in (tokenize.INDENT, tokenize.NEWLINE, None):
                    if tokval.startswith(("'''", '"""')):
                        continue

            # 4. Prevent consecutive NEWLINE tokens
            if toktype == tokenize.NEWLINE:
                if prev_toktype == tokenize.NEWLINE or prev_toktype is None:
                    continue

            result.append((toktype, tokval))
            prev_toktype = toktype

        # untokenize() expects a list of 2-tuples (type, string)
        minified = tokenize.untokenize(result)
        
        # Final cleanup: untokenize can sometimes leave trailing spaces 
        # or weird artifacts depending on the Python version.
        clean_lines = [line.rstrip() for line in minified.splitlines() if line.strip()]
        final_code = "\n".join(clean_lines)

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(final_code)
            
        print(f"Successfully minified: {output_path}")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python minifier.py <input_file.py>")
    else:
        minify_python(sys.argv[1])