#!/usr/bin/env python3
from pathlib import Path
import sys
root, out=map(Path,sys.argv[1:])
parts=['#pragma once\nnamespace cs {\n']
for name, file in [('index','index.html'),('css','style.css'),('js','app.js')]:
    text=(root/file).read_text()
    assert ')CSCAN_ASSET"' not in text
    parts.append(f'inline constexpr const char *web_{name}=R"CSCAN_ASSET({text})CSCAN_ASSET";\n')
parts.append('}\n')
out.write_text(''.join(parts))
