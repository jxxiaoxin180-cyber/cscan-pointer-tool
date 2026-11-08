#!/usr/bin/env python3
import urllib.parse, http.client, json, os, re, socket, subprocess, sys, tempfile, time, unittest
from pathlib import Path
BINARY=str(Path(sys.argv[1] if len(sys.argv)>1 else 'build-host/cscan').resolve())
sys.argv=sys.argv[:1]
class API(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.temp=tempfile.TemporaryDirectory(prefix='cscan-api-');cls.data=Path(cls.temp.name)
  sock=socket.socket();sock.bind(('127.0.0.1',0));cls.port=sock.getsockname()[1];sock.close()
  cls.log=open(cls.data/'server.log','w');cls.proc=subprocess.Popen([BINARY,'serve','--port',str(cls.port),'--data',str(cls.data)],stdout=cls.log,stderr=cls.log)
  for _ in range(100):
   try:
    c=http.client.HTTPConnection('127.0.0.1',cls.port,timeout=2);c.request('GET','/');r=c.getresponse();html=r.read().decode();c.close()
    cls.token=re.search(r'name="cscan-token" content="([a-f0-9]+)"',html).group(1);break
   except (OSError,AttributeError):
    if cls.proc.poll() is not None: raise RuntimeError('server failed: '+(cls.data/'server.log').read_text())
    time.sleep(.1)
  else:raise RuntimeError('server startup timeout')
 @classmethod
 def tearDownClass(cls):
  cls.proc.terminate();cls.proc.wait(timeout=10);cls.log.close();cls.temp.cleanup()
 def request(self,path,body=None,headers=None,auth=True):
  h={'X-CSCAN-Token':self.token} if auth else {}
  if body is not None:h['Content-Type']='application/json'
  if headers:h.update(headers)
  c=http.client.HTTPConnection('127.0.0.1',self.port,timeout=15)
  c.request('POST' if body is not None else 'GET',path,body if isinstance(body,(str,bytes)) else json.dumps(body) if body is not None else None,h)
  r=c.getresponse();raw=r.read();code=r.status;c.close()
  try:data=json.loads(raw)
  except (json.JSONDecodeError,UnicodeDecodeError):data=raw
  return code,data
 def task(self,req):
  code,d=self.request('/api/task',req);self.assertEqual(code,202,d);return self.wait()
 def wait(self):
  for _ in range(200):
   _,s=self.request('/api/task')
   if s['status']!='running':return s
   time.sleep(.03)
  self.fail('task did not finish')
 def fixture(self):
  code,d=self.request('/api/demo',{});self.assertEqual(code,200);d.update(kind='scan',reader='syscall');return d
 def test_01_requires_token(self):self.assertEqual(self.request('/api/files',auth=False)[0],403)
 def test_02_rejects_foreign_origin(self):self.assertEqual(self.request('/api/files',headers={'Origin':'https://example.invalid'})[0],403)
 def test_03_rejects_rebinding_host(self):self.assertEqual(self.request('/api/files',headers={'Host':'evil.invalid'})[0],403)
 def test_04_bad_json(self):self.assertEqual(self.request('/api/task','{broken')[0],400)
 def test_05_bad_file_path(self):self.assertEqual(self.request('/api/preview?file=..%2Fanything')[0],400)
 def test_06_fixture_scan_relation_filter(self):
  req=self.fixture();a=self.task(req);self.assertEqual(a['status'],'success',a);self.assertEqual(a['result']['count'],2);self.assertEqual(a['result']['format'],'CSCAN/2');self.assertEqual(a['result']['representation'],'graph');self.assertGreater(a['result']['graph_nodes'],2)
  file=a['result']['file'];_,p=self.request('/api/preview?file='+file);self.assertEqual(len(p['rows']),2)
  b=self.task(dict(req,kind='trace',chains=p['rows'][0]['text']));self.assertEqual(b['result']['traces'][0]['int32'],424242)
  f=self.task(dict(req,kind='filter',file=file));self.assertEqual(f['result']['count'],2)
  rel=self.task(dict(req,kind='relation'));self.assertEqual(rel['result']['count'],2)
  _,prev=self.request('/api/preview?file='+rel['result']['file']);trace=self.task(dict(req,kind='trace',chains=prev['rows'][0]['text']));self.assertEqual(trace['result']['traces'][0]['int32'],424242)
 def test_07_negative_filter_no_false_matches(self):
  req=self.fixture();a=self.task(req);r=self.task(dict(req,kind='filter',file=a['result']['file'],addresses='0x1234'));self.assertEqual(r['result']['count'],0)
 def test_08_empty_addresses_error_not_zero_results(self):
  req=self.fixture();r=self.task(dict(req,addresses=''));self.assertEqual(r['status'],'error');self.assertIn('目标地址',r['error'])
 def test_09_standard_pread(self):
  req=self.fixture();r=self.task(dict(req,reader='pread'));self.assertEqual(r['status'],'success');self.assertEqual(r['result']['count'],2)
 def test_10_import_compare_export(self):
  a=self.task({'kind':'import','text':'libx.so[1][Cd] + 0x10 -> + 0x20\nlibx.so[1][Cd] + 0x30\n','output':'input_a.cptr'});self.assertEqual(a['status'],'success',a)
  b=self.task({'kind':'import','text':'libx.so[1][Cd] + 0x10 -> + 0x20\nlibx.so[1][Cd] + 0x40\n','output':'input_b.cptr'})
  req={'kind':'compare','files':['input_a.cptr','input_b.cptr']};c=self.task(req);self.assertEqual(c['result']['count'],1)
  _,raw=self.request('/api/export?file='+c['result']['file']);self.assertIn(b'libx.so[1][Cd] + 0x10 -> + 0x20',raw)
  count=self.task(dict(req,kind='count'));self.assertEqual(count['result']['count'],1);self.assertNotIn('file',count['result'])
 def test_11_no_overwrite(self):
  r=self.task({'kind':'import','text':'libx.so[1][Cd] + 0x1','output':'input_a.cptr'});self.assertEqual(r['status'],'error')
 def test_12_concurrency_and_cancel(self):
  code,d=self.request('/api/task',{'kind':'import','text':'libbig.so[1][Cd] + 0x10\n'*150000,'output':'cancelled.cptr'});self.assertEqual(code,202,d)
  self.assertEqual(self.request('/api/task',{'kind':'import','text':'@start + 0x1'})[0],409)
  self.assertEqual(self.request('/api/files/delete',{'files':['cancelled.cptr']})[0],409)
  self.assertEqual(self.request('/api/cancel',{})[0],200)
  r=self.wait();self.assertEqual(r['status'],'cancelled',r);self.assertFalse((self.data/'cancelled.cptr').exists())
 def test_13_incomplete_result_limit(self):
  r=self.task(dict(self.fixture(),limit=1));self.assertEqual(r['status'],'partial');self.assertEqual(r['result']['count'],1);self.assertEqual(r['result']['reason'],'result_limit')
 def test_14_invalid_reader_reported(self):
  r=self.task(dict(self.fixture(),reader='not-a-reader'));self.assertEqual(r['status'],'error');self.assertIn('读取器',r['error'])
 def test_15_file_integrity_and_download(self):
  r=self.task(self.fixture());name=r['result']['file'];code,b=self.request('/api/download?file='+name);self.assertEqual(code,200);self.assertEqual(b[:8],b'CSCAN02\n')
  damaged=bytearray(b);damaged[-1]^=1;(self.data/'bad.cptr').write_bytes(damaged)
  self.assertEqual(self.request('/api/preview?file=bad.cptr')[0],400)
 def test_16_input_bit_width(self):
  r=self.task(dict(self.fixture(),bits=32));self.assertEqual(r['status'],'error')
 def test_17_incomplete_import_preserved(self):
  r=self.task({'kind':'import','text':'# CSCAN-TXT 1 {"bits":64,"mask":"none","complete":false}\nlibx.so[1][Cd] + 0x1\n'});self.assertEqual(r['status'],'partial');self.assertEqual(r['result']['reason'],'incomplete_input')
 def test_18_module_query(self):
  d=self.fixture();code,m=self.request('/api/modules?pid='+str(d['pid']));self.assertEqual(code,200);self.assertTrue(any(x['id']==d['modules'][0] for x in m['modules']))
 def test_19_selected_identity_cannot_change(self):
  r=self.task(dict(self.fixture(),identity='wrong-start-time'));self.assertEqual(r['status'],'error');self.assertIn('PID',r['error'])
 def test_20_mixed_width_text_export_roundtrip(self):
  r=self.task({'kind':'import','text':'# CSCAN-TXT 1 {"bits":32,"mask":"none","complete":true}\nlibx.so[1][Cd] + 0x10\n# CSCAN-TXT 1 {"bits":64,"mask":"topbyte","complete":true}\nlibx.so[1][Cd] + 0x20\n'})
  self.assertEqual(r['status'],'success',r)
  _,out=self.request('/api/export?file='+r['result']['file']);self.assertEqual(out.count(b'# CSCAN-TXT'),2)
  r=self.task({'kind':'import','text':out.decode()});_,p=self.request('/api/preview?file='+r['result']['file']);self.assertEqual([x['bits'] for x in p['rows']],[32,64]);self.assertEqual(p['rows'][1]['mask'],'topbyte')
 def test_21_process_catalog_visibility(self):
  code,catalog=self.request('/api/process-list');self.assertEqual(code,200);self.assertEqual(catalog['count'],len(catalog['processes']));self.assertIn('kernel_euid',catalog['runtime']);self.assertTrue(all('metadata_complete' in p and 'state' in p for p in catalog['processes']))
 def test_22_own_pid_diagnostic(self):
  req=self.fixture();code,d=self.request('/api/process?pid='+str(req['pid']));self.assertEqual(code,200);self.assertTrue(d['connectable']);self.assertTrue(d['maps_readable']);self.assertIn('kernel_euid',d['runtime'])
 def test_23_invisible_pid_honest_state(self):
  code,d=self.request('/api/process?pid=2147483647');self.assertEqual(code,200);self.assertEqual(d['state'],'not_visible');self.assertFalse(d['connectable']);self.assertIn('不能',d['message'])
 def test_24_normal_reader_and_memory_view(self):
  req=self.fixture();r=self.task(dict(req,reader='normal',kind='read-memory',size=64));self.assertEqual(r['status'],'success',r);result=r['result'];self.assertEqual(result['bytes_read'],64);self.assertEqual(result['values']['int32'],424242);self.assertEqual(result['values']['int64'],'424242');self.assertTrue(result['reader_info']['read_verified']);self.assertGreater(result['reader_info']['syscall_reads'],0)
 def test_25_channel_open_not_read_verified(self):
  r=self.task({'kind':'backend-status','reader':'syscall'});self.assertEqual(r['status'],'success');self.assertTrue(r['result']['reader_info']['channel_open']);self.assertFalse(r['result']['reader_info']['read_verified'])
 def test_26_invalid_backend_never_silently_falls_back(self):
  r=self.task({'kind':'backend-status','reader':'bad-reader'});self.assertEqual(r['status'],'partial');self.assertFalse(r['result']['available']);self.assertIn('不支持',r['result']['error'])
 def test_27_memory_view_bounds(self):
  r=self.task(dict(self.fixture(),kind='read-memory',size=4097));self.assertEqual(r['status'],'error')
 def test_28_format_text_task(self):
  r=self.task({'kind':'import','text':'libx.so[1][Cd] + 0x10 -> + 0x20\n','output':'format-input.cptr'});self.assertEqual(r['status'],'success')
  formatted=self.task({'kind':'format','file':'format-input.cptr'});self.assertEqual(formatted['status'],'success',formatted);self.assertTrue(formatted['result']['file'].endswith('.txt'))
  code,raw=self.request('/api/text-download?file='+formatted['result']['file']);self.assertEqual(code,200);self.assertIn(b'# CSCAN-TXT 1',raw);self.assertIn(b'libx.so[1][Cd] + 0x10 -> + 0x20',raw)
 def test_29_native_download_ticket(self):
  result=self.task(self.fixture())['result'];name=result['file']
  code,grant=self.request('/api/download-ticket',{'endpoint':'download','file':name,'graph_memory_mb':128});self.assertEqual(code,200)
  query=urllib.parse.urlencode({'file':name,'ticket':grant['ticket'],'graph_memory_mb':128})
  code,raw=self.request('/api/download?'+query,auth=False);self.assertEqual(code,200);self.assertEqual(raw[:8],b'CSCAN02\n')
  self.assertEqual(self.request('/api/download?'+query,auth=False)[0],403)
  self.assertEqual(self.request('/api/download-ticket',{'endpoint':'download','file':name},auth=False)[0],403)
 def test_30_large_file_chunk_upload_and_import(self):
  payload=b'# '+b'x'*1021+b'\n'
  data=payload*9000+b'liblarge.so[1][Cd] + 0x10 -> + 0x20\n'
  self.assertGreater(len(data),8*1024*1024)
  code,session=self.request('/api/upload/start',{'name':'large.txt','bytes':len(data)});self.assertEqual(code,200)
  self.assertEqual(self.request('/api/upload/finish',{'id':session['id']})[0],400)
  for offset in range(0,len(data),session['chunk_bytes']):
   code,result=self.request('/api/upload/chunk?'+urllib.parse.urlencode({'id':session['id'],'offset':offset}),data[offset:offset+session['chunk_bytes']],headers={'Content-Type':'application/octet-stream'});self.assertEqual(code,200,result)
  code,result=self.request('/api/upload/finish',{'id':session['id']});self.assertEqual(code,200)
  imported=self.task({'kind':'import','file':result['file']});self.assertEqual(imported['status'],'success',imported);self.assertEqual(imported['result']['count'],1)
 def test_31_upload_abort_removes_temporary_file(self):
  _,session=self.request('/api/upload/start',{'name':'cancel.txt','bytes':10})
  self.assertEqual(self.request('/api/upload/chunk?id='+session['id']+'&offset=1',b'abc')[0],400)
  self.assertEqual(self.request('/api/upload/cancel',{'id':session['id']})[0],200)
  self.assertFalse(list(self.data.glob('.'+session['id']+'*')))
 def test_32_filter_formatted_text_against_current_address(self):
  req=self.fixture();scan=self.task(req)['result'];formatted=self.task({'kind':'format','file':scan['file']})['result']
  filtered=self.task(dict(req,kind='filter',file=formatted['file']));self.assertEqual(filtered['status'],'success',filtered);self.assertEqual(filtered['result']['count'],2)
  wrong=self.task(dict(req,kind='filter',file=formatted['file'],addresses='0x1234'));self.assertEqual(wrong['result']['count'],0)
 def test_33_filter_direct_text_output(self):
  req=self.fixture();first=self.task(req)['result']['file'];original=(self.data/first).read_bytes()
  result=self.task(dict(req,kind='filter',file=first,bits='64',graph_memory_mb='128',output_format='text',output='matched.txt'))
  self.assertEqual(result['status'],'success',result);out=result['result'];self.assertEqual(out['count'],2);self.assertEqual(out['kind'],'filter');self.assertEqual(out['output_format'],'text');self.assertEqual(out['file'],'matched.txt')
  code,raw=self.request('/api/text-download?file=matched.txt');self.assertEqual(code,200)
  header=json.loads(raw.decode().splitlines()[0][14:]);self.assertEqual(header['kind'],'filter');self.assertTrue(header['complete']);self.assertEqual(header['count'],2);self.assertEqual(header['source'],first)
  _,preview=self.request('/api/preview?file=matched.txt');self.assertEqual(len(preview['rows']),2)
  _,files=self.request('/api/files');self.assertTrue(any(f['file']=='matched.txt' for f in files))
  self.assertEqual((self.data/first).read_bytes(),original);self.assertFalse(list(self.data.glob('*.part')))
 def test_34_text_filter_zero_matches_and_reuse(self):
  req=self.fixture();first=self.task(req)['result']['file'];txt=self.task(dict(req,kind='filter',file=first,output_format='text'))['result']['file']
  back=self.task(dict(req,kind='filter',file=txt,output_format='binary'));self.assertEqual(back['result']['count'],2);self.assertTrue(back['result']['file'].endswith('.cptr'))
  zero=self.task(dict(req,kind='filter',file=txt,addresses='0x1234',output_format='text'));self.assertEqual(zero['status'],'success',zero);self.assertEqual(zero['result']['count'],0)
  _,preview=self.request('/api/preview?file='+zero['result']['file']);self.assertEqual(preview['rows'],[])
 def test_35_text_filter_preserves_limit_status(self):
  req=self.fixture();first=self.task(req)['result']['file'];out=self.task(dict(req,kind='filter',file=first,output_format='text',limit=1))
  self.assertEqual(out['status'],'partial',out);self.assertEqual(out['result']['count'],1);self.assertEqual(out['result']['reason'],'result_limit')
  header=json.loads((self.data/out['result']['file']).read_text().splitlines()[0][14:]);self.assertFalse(header['complete']);self.assertEqual(header['reason'],'result_limit')
 def test_36_text_filter_no_overwrite_or_invalid_format(self):
  req=self.fixture();first=self.task(req)['result']['file'];(self.data/'keep.txt').write_text('keep')
  bad=self.task(dict(req,kind='filter',file=first,output_format='text',output='keep.txt'));self.assertEqual(bad['status'],'error');self.assertEqual((self.data/'keep.txt').read_text(),'keep')
  bad=self.task(dict(req,kind='filter',file=first,output_format='xml'));self.assertEqual(bad['status'],'error')
  bad=self.task(dict(req,kind='filter',file=first,output_format='text',output='wrong.cptr'));self.assertEqual(bad['status'],'error')
 def test_37_delete_binary_text_and_corrupt_results(self):
  req=self.fixture();file=self.task(req)['result']['file']
  txt=self.task(dict(req,kind='filter',file=file,output_format='text'))['result']['file']
  (self.data/'broken.cptr').write_bytes(b'broken')
  code,result=self.request('/api/files/delete',{'files':[file,txt,'broken.cptr',file]})
  self.assertEqual(code,200,result);self.assertEqual(set(result['deleted']),{file,txt,'broken.cptr'});self.assertEqual(result['failed'],[])
  _,files=self.request('/api/files');self.assertFalse(any(f['file'] in result['deleted'] for f in files))
  self.assertTrue(all(not (self.data/f).exists() for f in result['deleted']))
 def test_38_delete_requires_auth_and_local_origin(self):
  (self.data/'auth-keep.txt').write_text('keep')
  body={'files':['auth-keep.txt']}
  self.assertEqual(self.request('/api/files/delete',body,auth=False)[0],403)
  self.assertEqual(self.request('/api/files/delete',body,headers={'Origin':'https://example.invalid'})[0],403)
  self.assertEqual((self.data/'auth-keep.txt').read_text(),'keep')
 def test_39_delete_validates_entire_batch_and_paths(self):
  keep=self.data/'delete-keep.txt';keep.write_text('keep');(self.data/'directory.txt').mkdir();(self.data/'link.txt').symlink_to(keep)
  bad=['../outside.txt','/tmp/outside.txt','server.log','.hidden.txt','directory.txt','link.txt','nul\x00.txt']
  for name in bad:
   code,_=self.request('/api/files/delete',{'files':['delete-keep.txt',name]});self.assertEqual(code,400,name);self.assertEqual(keep.read_text(),'keep')
  for files in [[],['delete-keep.txt']*101,'delete-keep.txt',[5]]:
   self.assertEqual(self.request('/api/files/delete',{'files':files})[0],400);self.assertTrue(keep.exists())
 def test_40_delete_reports_missing_without_hiding_success(self):
  (self.data/'remove-present.txt').write_text('remove')
  code,result=self.request('/api/files/delete',{'files':['remove-present.txt','missing-delete.txt']})
  self.assertEqual(code,200);self.assertEqual(result['deleted'],['remove-present.txt']);self.assertEqual(result['failed'][0]['file'],'missing-delete.txt')
 def test_41_delete_blocked_during_upload(self):
  (self.data/'upload-keep.txt').write_text('keep')
  _,upload=self.request('/api/upload/start',{'name':'busy.txt','bytes':10})
  try:
   self.assertEqual(self.request('/api/files/delete',{'files':['upload-keep.txt']})[0],409)
   self.assertEqual((self.data/'upload-keep.txt').read_text(),'keep')
  finally:self.request('/api/upload/cancel',{'id':upload['id']})
 def test_42_delete_invalidates_unused_download_ticket(self):
  (self.data/'ticket-delete.txt').write_text('keep')
  _,ticket=self.request('/api/download-ticket',{'endpoint':'text-download','file':'ticket-delete.txt'})
  self.assertEqual(self.request('/api/files/delete',{'files':['ticket-delete.txt']})[0],200)
  (self.data/'ticket-delete.txt').write_text('replacement')
  path='/api/text-download?'+urllib.parse.urlencode(dict(file='ticket-delete.txt',ticket=ticket['ticket'],graph_memory_mb=128))
  self.assertEqual(self.request(path,auth=False)[0],403)
if __name__=='__main__':unittest.main(verbosity=2)
