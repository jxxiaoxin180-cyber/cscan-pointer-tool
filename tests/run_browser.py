#!/usr/bin/env python3
import os, socket, subprocess, sys, tempfile, time, urllib.request
from pathlib import Path
binary=str(Path(sys.argv[1] if len(sys.argv)>1 else 'build-host/cscan').resolve())
with tempfile.TemporaryDirectory(prefix='cscan-browser-') as work:
 s=socket.socket();s.bind(('127.0.0.1',0));port=s.getsockname()[1];s.close()
 with open(Path(work)/'server.log','w') as log:
  proc=subprocess.Popen([binary,'serve','--data',work,'--port',str(port)],stdout=log,stderr=log)
  try:
   for _ in range(100):
    try:urllib.request.urlopen(f'http://127.0.0.1:{port}/',timeout=2).close();break
    except OSError:time.sleep(.1)
   else:raise RuntimeError('startup timeout')
   env=dict(os.environ,CSCAN_URL=f'http://127.0.0.1:{port}')
   result=subprocess.run(['node','tests/browser.cjs'],env=env)
  finally:proc.terminate();proc.wait(timeout=10)
sys.exit(result.returncode)
