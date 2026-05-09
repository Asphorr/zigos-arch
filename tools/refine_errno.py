import re
import sys

path = sys.argv[1]
with open(path, 'r', encoding='utf-8') as f:
    src = f.read()

rules = [
    (r'(if \(!validateUserPtr\([^)]*\)\) return )E_INVAL;', r'\1E_FAULT;'),
    (r'(\.currentPCB\(\) orelse return )E_INVAL;', r'\1E_FAULT;'),
    (r'(\.page_directory orelse return )E_INVAL;', r'\1E_FAULT;'),
    (r'(\.allocContiguous\([^)]*\) orelse return )E_INVAL;', r'\1E_NOMEM;'),
    (r'(\.allocFrame\(\) orelse return )E_INVAL;', r'\1E_NOMEM;'),
    (r'(\.resolvePath\([^)]*\) orelse return )E_INVAL;', r'\1E_NOENT;'),
    (r'(if \(\w+_len == 0 or \w+_len >=? \d+\) return )E_INVAL;', r'\1E_NAMETOOLONG;'),
]
before = src.count('return E_INVAL;')
for pat, repl in rules:
    src = re.sub(pat, repl, src)
after = src.count('return E_INVAL;')
with open(path, 'w', encoding='utf-8') as f:
    f.write(src)
print(f'EINVAL {before} -> {after}')
print(f'EFAULT {src.count("return E_FAULT;")}')
print(f'ENOMEM {src.count("return E_NOMEM;")}')
print(f'ENOENT {src.count("return E_NOENT;")}')
print(f'ENAMETOOLONG {src.count("return E_NAMETOOLONG;")}')
