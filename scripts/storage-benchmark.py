#!/usr/bin/env python3
"""Compare verified CSCAN/1 and CSCAN/2 storage on the same synthetic chains."""
import argparse, hashlib, json, random, subprocess, tempfile, time
from pathlib import Path
parser=argparse.ArgumentParser()
parser.add_argument('--current',required=True)
parser.add_argument('--baseline',required=True)
parser.add_argument('--output',required=True)
args=parser.parse_args()
rng=random.Random(20261022)
lines=[]
for i in range(30000):
    offsets=[0x100+i*8]+[rng.randrange(251)*8 for _ in range(6)]
    lines.append('libstorage_probe.so[1][Cd] + '+' -> + '.join(f'0x{x:X}' for x in offsets))
payload='\n'.join(lines)+'\n'
report={'dataset':'synthetic; fixed seed 20261022; 30000 distinct chains; 6 dereferences; same module','chains':len(lines),'txt_chain_bytes':len(payload.encode()),'cases':[]}
with tempfile.TemporaryDirectory(prefix='cscan-storage-') as d:
    work=Path(d);source=work/'input.txt';source.write_text(payload)
    for name,binary in [('CSCAN/1',args.baseline),('CSCAN/2',args.current)]:
        binary=str(Path(binary).resolve());version=subprocess.check_output([binary,'--version'],text=True).strip()
        data=work/version;data.mkdir();start=time.monotonic()
        run=subprocess.run([binary,'import','--data',str(data),'--text-file',str(source),'--output','probe.cptr'],capture_output=True,text=True,check=True)
        meta=json.loads(run.stdout);elapsed=time.monotonic()-start
        exported=subprocess.check_output([binary,'export','--data',str(data),'--file','probe.cptr'],text=True)
        restored=[line for line in exported.splitlines() if line and not line.startswith('#')]
        if restored!=lines or meta['count']!=len(lines):raise RuntimeError('roundtrip mismatch')
        content=(data/'probe.cptr').read_bytes()
        report['cases'].append({'version':version,'format':name,'cptr_bytes':len(content),'fraction_of_text':len(content)/len(payload.encode()),'roundtrip_identical':True,'import_seconds':round(elapsed,6),'sha256':hashlib.sha256(content).hexdigest()})
report['scope']='Import/storage benchmark, no process scan. Ratios depend on workload. Timing includes process launch, parsing, compression and fsync.'
Path(args.output).write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
print(json.dumps(report,ensure_ascii=False,indent=2))
