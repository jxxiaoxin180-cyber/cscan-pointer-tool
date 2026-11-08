#!/usr/bin/env python3
import json, os, pty, select, subprocess, sys, tempfile, time, unittest
from pathlib import Path
BINARY=str(Path(sys.argv[1] if len(sys.argv)>1 else 'bin/cscan-android-arm64').resolve());sys.argv=sys.argv[:1]
class CLI(unittest.TestCase):
 def test_help(self):
  r=subprocess.run([BINARY,'--help'],capture_output=True,text=True,timeout=10);self.assertEqual(r.returncode,0);self.assertIn('C扫指针工具第一版',r.stdout)
 def test_version(self):self.assertEqual(subprocess.check_output([BINARY,'--version'],text=True).strip(),'1.2.2')
 def test_real_pty_menu_exit(self):
  with tempfile.TemporaryDirectory() as d:
   master,slave=pty.openpty();p=subprocess.Popen([BINARY,'menu','--data',d],stdin=slave,stdout=slave,stderr=slave);os.close(slave);data=b''
   try:
    deadline=time.monotonic()+10
    while time.monotonic()<deadline:
     if select.select([master],[],[],.2)[0]:
      data+=os.read(master,8192)
      if '选择 [1]'.encode() in data:break
    self.assertIn('选择 [1]',data.decode())
    os.write(master,b'0\n');self.assertEqual(p.wait(timeout=5),0)
   finally:
    if p.poll() is None:p.terminate();p.wait(timeout=5)
    os.close(master)
 def test_config_import_and_export(self):
  with tempfile.TemporaryDirectory() as d:
   cfg=Path(d)/'request.json';cfg.write_text(json.dumps({'text':'libcli.so[1][Cd] + 0x20 -> - 0x10','output':'cli.cptr'}))
   r=subprocess.run([BINARY,'import','--config',str(cfg),'--data',d],capture_output=True,text=True,timeout=10);self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(json.loads(r.stdout)['count'],1)
   out=subprocess.check_output([BINARY,'export','--data',d,'--file','cli.cptr'],text=True);self.assertIn('-> - 0x10',out)
 def test_format_command(self):
  with tempfile.TemporaryDirectory() as d:
   r=subprocess.run([BINARY,'import','--data',d,'--text','libcli.so[1][Cd] + 0x20 -> - 0x10','--output','cli.cptr'],capture_output=True,text=True,timeout=10);self.assertEqual(r.returncode,0,r.stderr)
   r=subprocess.run([BINARY,'format','--data',d,'--file','cli.cptr','--output','cli.txt'],capture_output=True,text=True,timeout=10);self.assertEqual(r.returncode,0,r.stderr);self.assertTrue((Path(d)/'cli.txt').exists());self.assertIn('# CSCAN-TXT 1', (Path(d)/'cli.txt').read_text());self.assertIn('-> - 0x10',(Path(d)/'cli.txt').read_text())
 def test_invalid_parameter_exit(self):
  r=subprocess.run([BINARY,'scan','--pid','123abc'],capture_output=True,text=True,timeout=10);self.assertEqual(r.returncode,1);self.assertIn('error',json.loads(r.stderr))
 def test_non_tty_menu_eof(self):
  with tempfile.TemporaryDirectory() as d:
   r=subprocess.run([BINARY,'menu','--data',d],input='',capture_output=True,text=True,timeout=10);self.assertEqual(r.returncode,0)
 def test_runtime_credentials(self):
  with tempfile.TemporaryDirectory() as d:
   r=subprocess.run([BINARY,'runtime'],cwd=d,capture_output=True,text=True,timeout=10);self.assertEqual(r.returncode,0,r.stderr);data=json.loads(r.stdout);self.assertEqual(data['root'],data['kernel_euid']==0);self.assertFalse((Path(d)/'cscan-data').exists())
 def test_pid_diagnostic(self):
  r=subprocess.run([BINARY,'diagnose-pid','--pid','2147483647'],capture_output=True,text=True,timeout=10);self.assertEqual(r.returncode,2);self.assertEqual(json.loads(r.stdout)['state'],'not_visible')
 def test_backend_status(self):
  r=subprocess.run([BINARY,'backend-status','--reader','normal'],capture_output=True,text=True,timeout=10);self.assertEqual(r.returncode,0);self.assertFalse(json.loads(r.stdout)['reader_info']['read_verified'])
 def test_large_text_file_streaming(self):
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/'large.txt'
   with path.open('w') as stream:
    for _ in range(9000):stream.write('# '+'x'*1021+'\n')
    stream.write('libcli.so[1][Cd] + 0x40 -> + 0x20\n')
   r=subprocess.run([BINARY,'import','--data',d,'--text-file',str(path)],capture_output=True,text=True,timeout=30);self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(json.loads(r.stdout)['count'],1)
if __name__=='__main__':unittest.main(verbosity=2)
