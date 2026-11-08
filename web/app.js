'use strict';
const $=id=>document.getElementById(id), token=document.querySelector('meta[name=cscan-token]').content;
const state={page:'scan',mode:'scan',processes:[],modules:[],selectedModules:[],draftModules:new Set(),files:[],selectedFiles:new Set(),target:null,spans:[],demo:false,busy:false,task:null,seenTask:'',resultFile:null,resultPage:0,epoch:0,submitting:false,expectedTask:'',runtime:null};
const names={scan:'扫描指针',results:'文件对比',filter:'加载链条过滤',trace:'链条调试',settings:'读取器设置'};
const kindLabels={scan:'扫描文件',relation:'地址关系',compare:'对比结果',filter:'过滤结果',import:'导入文件',format:'文本文件',text:'链文本'};
const readers={normal:['普通自动','syscall → pread'],paradise:['Paradise','自动识别协议'],syscall:['系统调用','process_vm_readv'],pread:['备用读取','/proc/PID/mem'],paradise35:['Paradise 3.5','直接驱动接口'], 'paradise-hook':['Paradise Hook','旧版 socket 协议']};
const statusNames={idle:'待开始',running:'运行中',success:'已完成',partial:'不完整',cancelled:'已停止',error:'失败'};
const reasons={result_limit:'达到结果数量上限',memory_limit:'达到指针索引预算',time_limit:'达到任务时限',work_limit:'达到搜索工作量上限',read_failures:'部分内存区域读取失败',incomplete_input:'输入结果本身不完整',cancelled:'用户停止了任务',graph_memory_limit:'达到图内存预算',graph_node_limit:'达到图节点上限',backend_unavailable:'读取通道不可用',short_read:'只读取到部分字节'};
function el(tag,cls,text){const e=document.createElement(tag);if(cls)e.className=cls;if(text!==undefined)e.textContent=text;return e;}
function tell(msg,error=false){$('notice').textContent=msg;$('notice').className='notice'+(error?' error':'');$('notice').hidden=false;}
function clearNotice(){$('notice').hidden=true;}
async function api(path,body){const options={headers:{'X-CSCAN-Token':token}};if(body!==undefined){options.method='POST';options.headers['Content-Type']='application/json';options.body=JSON.stringify(body);}const response=await fetch('/api/'+path,options);let data;try{data=await response.json();}catch{throw Error('服务返回无效响应，请检查终端输出。');}if(!response.ok)throw Error(data.error||'请求失败');return data;}
function guard(fn){return async(...args)=>{try{await fn(...args);}catch(e){tell(e.message,true);}};}
function page(id){if(!names[id])id='scan';state.page=id;document.querySelectorAll('.page').forEach(e=>{const active=e.id==='page-'+id;e.hidden=!active;e.classList.toggle('active',active);});document.querySelectorAll('.nav-item').forEach(e=>e.classList.toggle('active',e.dataset.page===id));$('page-label').textContent=names[id];history.replaceState(null,'','#'+id);if(id==='filter'){syncFilterTarget();renderFilterFiles();}}
function num(id){const n=Number($(id).value);if(!Number.isSafeInteger(n)||n<0)throw Error('请检查 '+$(id).closest('label').firstChild.textContent);return n;}
function base(){if(!state.target||num('pid')!==state.target.pid)throw Error('请先连接目标进程，确认 PID 和模块。');return {pid:state.target.pid,identity:state.target.identity,uid:state.target.uid,bits:num('bits'),reader:$('reader').value,mask:$('mask').value,source:$('source').value.trim(),graph_memory_mb:num('graph-memory-mb'),timeout:num('timeout')};}
function scanConfig(){const b=base(),output=$('scan-output').value.trim();return {...b,...(output?{output:output.endsWith('.cptr')?output:output+'.cptr'}:{}),kind:state.mode,addresses:$('addresses').value.trim(),depth:num('depth'),offset:$('offset').value.trim(),limit:num('limit'),memory_mb:num('memory-mb'),negative:state.mode==='scan'&&$('negative').checked,nonread:$('nonread').checked,step:$('step4').checked||b.bits===32?4:8,modules:state.mode==='scan'?state.selectedModules:[],ranges:[...document.querySelectorAll('.ranges input:checked')].map(e=>e.value),layer_offsets:state.mode==='scan'?$('layer-offsets').value.trim():'',graph_memory_mb:num('graph-memory-mb'),threads:num('threads'),...(state.spans.length?{spans:state.spans}:{})};}
function updateSummary(){if($('offset').oninput)$('offset').oninput();const t=state.target;let name=t? t.name.split('/').pop():'尚未选择';$('stat-target').textContent=state.demo?'内置自测样本':name;$('stat-target').title=name;$('stat-pid').textContent=t?'PID '+t.pid+' · UID '+t.uid:'选择一个运行中的进程';$('target-name').textContent=t?(state.demo?'自测样本 · 已限定到样本内存区间':t.name):'连接后可选择模块并测试读取器';$('target-state').textContent=t?(state.demo?'自测样本':'已连接'):'未连接';$('target-state').className='badge '+(t?'success':'neutral');$('trace-target').textContent=t?'PID '+t.pid:'未选择进程';const m=state.selectedModules.length;const summary=m?m+' 个根模块':'全部根模块';$('stat-modules').textContent=summary;$('module-summary').textContent=summary;const r=readers[$('reader').value];$('stat-reader').textContent=r[0];$('stat-reader-detail').textContent=r[1];document.querySelectorAll('[data-reader]').forEach(e=>e.classList.toggle('selected',e.dataset.reader===$('reader').value));}
function renderRuntime(runtime){
 state.runtime=runtime;if(!runtime)return;
 $('runtime-uid').textContent=runtime.kernel_euid>=0?String(runtime.kernel_euid):'未知';
 $('runtime-scope').textContent=runtime.root?'原生 Root 可见范围':'当前普通权限可见范围';
 $('runtime-banner').hidden=false;$('runtime-banner').className='runtime-banner '+(runtime.root?'root':'limited');
 $('runtime-banner').textContent=runtime.root?'原生 Root · 内核 UID 0 · 进程访问仍以实际结果为准':`${runtime.message}。查找其他应用时，请使用“以Root启动.sh”或在原生 Root 终端直接运行程序。`;
}
async function refreshProcesses(){const data=await api('process-list');state.processes=data.processes;renderRuntime(data.runtime);$('process-count').textContent=`当前可见 ${data.count} 个进程 · ${data.restricted_count} 个信息受限`;renderProcesses();}
async function diagnosePid(pid){
 if(!Number.isSafeInteger(pid)||pid<=0)throw Error('请输入有效的十进制 PID。');
 const d=await api('process?pid='+encodeURIComponent(pid));renderRuntime(d.runtime);
 let msg=`PID ${d.pid} · ${d.name}\n${d.message}\n启动身份：${d.identity||'不可读'} · maps：${d.maps_readable?'可读':'不可读'}\n内核 UID：${d.runtime.kernel_euid}`;
 if(d.errors.length)msg+='\n'+d.errors.map(e=>`${e.field}: errno=${e.errno} ${e.message}`).join('\n');
 $('process-diagnostics').textContent=msg;$('process-diagnostics').hidden=false;tell(`PID ${d.pid}：${d.message}${d.runtime.root?'':'。当前为普通权限。'}`,!d.connectable);return d;
}
function renderProcesses(){const q=$('process-query').value.trim().toLowerCase();const list=$('process-list');list.replaceChildren();const items=state.processes.filter(p=>[p.name,p.pid,p.uid].join(' ').toLowerCase().includes(q));
 if(!items.length){list.append(el('p','help-text','当前权限下没有匹配项。这不代表应用一定未运行；可输入 PID 后单独检测。'));return;}
 for(const p of items){const button=el('button','picker-item');const span=el('span');span.append(el('b','',p.name),el('small','',`PID ${p.pid} · UID ${p.uid>=0?p.uid:'未知'} · ${p.bits||'未知'} 位${p.metadata_complete?'':' · 部分信息不可读'}`));button.append(span,el('span','text-button',p.connectable?'连接 →':'查看原因'));button.onclick=guard(async()=>{if(!p.connectable){await diagnosePid(p.pid);return;}await connect(p.pid);$('process-dialog').close();});list.append(button);}
}
async function connect(pid){const data=await api('modules?pid='+encodeURIComponent(pid));if(state.target&&(state.target.pid!==data.pid||state.target.identity!==data.identity)){$('filter-address').value='';$('filter-source').value='';}state.target=data;state.modules=data.modules;state.selectedModules=[];state.spans=[];state.demo=false;$('pid').value=pid;$('process-search').value=data.name;if(data.bits)$('bits').value=data.bits;updateSummary();syncFilterTarget();tell('已连接进程。建议先测试读取器，再开始扫描。');}
async function demo(){const d=await api('demo',{});await connect(d.pid);state.demo=true;state.spans=d.spans;state.selectedModules=d.modules;for(const id of ['addresses','source','depth','offset','bits'])$(id).value=d[id];$('memory-address').value=d.addresses;$('reader').value='syscall';$('negative').checked=false;$('layer-offsets').value='';$('mask').value='none';$('limit').value='100000';$('timeout').value='120';document.querySelectorAll('.ranges input').forEach(e=>e.checked=['A','Cd'].includes(e.value));setMode('scan');updateSummary();page('scan');tell('已载入真实的进程内存样本：2 条已知路径。点击“开始扫描”，然后可在结果中调试，最终值应为 424242。');}
function setMode(mode){state.mode=mode;$('mode-scan').classList.toggle('active',mode==='scan');$('mode-relation').classList.toggle('active',mode==='relation');$('source-field').hidden=mode!=='relation';$('negative').disabled=mode==='relation';$('layer-offsets').disabled=mode==='relation';$('choose-modules').disabled=mode==='relation';$('depth').min=mode==='relation'?'1':'0';}
function renderModules(){const list=$('module-list');list.replaceChildren();const q=$('module-query').value.toLowerCase();for(const m of state.modules.filter(m=>m.id.toLowerCase().includes(q))){const label=el('label','picker-item'),check=document.createElement('input');check.type='checkbox';check.checked=state.draftModules.has(m.id);check.onchange=()=>{check.checked?state.draftModules.add(m.id):state.draftModules.delete(m.id);$('module-selected-label').textContent='已选 '+state.draftModules.size+' 个';};const content=el('span');content.append(el('b','',m.id),el('small','',`${m.start} – ${m.end} · ${m.perms}`));label.append(check,content);list.append(label);}$('module-selected-label').textContent='已选 '+state.draftModules.size+' 个';}
async function refreshFiles(){state.files=await api('files');const valid=new Set(state.files.map(x=>x.file));state.selectedFiles.forEach(f=>{if(!valid.has(f))state.selectedFiles.delete(f);});$('file-count').textContent=state.files.length;$('stat-files').replaceChildren(document.createTextNode(String(state.files.length).padStart(2,'0')),el('small','',' 份'));if(state.resultFile&&!valid.has(state.resultFile)){state.resultFile=null;$('result-detail').hidden=true;}
 if(state.filterUploaded&&!valid.has(state.filterUploaded.file))state.filterUploaded=null;
 renderFiles();renderFilterFiles();syncDeletedOutputs();}
function syncDeletedOutputs(){
 const missing=file=>file&&!state.files.some(f=>f.file===file);
 if(missing(state.task?.result?.file))$('open-task-result').hidden=true;
 if(missing(state.compareTask?.result?.file))$('compare-view-output').hidden=true;
 if(missing(state.filterTask?.result?.file)){$('filter-view-output').hidden=true;$('filter-download-output').hidden=true;}
}
function confirmDelete(files){
 if(state.busy||state.uploading||state.deleting){tell('任务或上传正在进行，请结束后再删除文件。',true);return;}
 state.deleteFiles=[...files];$('delete-file-list').replaceChildren(...files.map(file=>el('li','mono',file)));
 $('delete-title').textContent=`确认删除 ${files.length} 个文件`;$('delete-error').hidden=true;
 $('delete-confirm').textContent='确认删除';$('delete-dialog').showModal();$('delete-cancel').focus();
}
$('delete-selected').onclick=()=>confirmDelete([...state.selectedFiles]);
$('delete-cancel').onclick=()=>{if(!state.deleting)$('delete-dialog').close();};
$('delete-dialog').addEventListener('cancel',event=>{if(state.deleting)event.preventDefault();});
$('delete-confirm').onclick=async()=>{
 if(state.deleting)return;
 state.deleting=true;updateSelected();$('delete-cancel').disabled=true;$('delete-confirm').textContent='正在删除…';$('delete-error').hidden=true;
 try{
  const result=await api('files/delete',{files:state.deleteFiles});
  state.deleteFiles=result.failed.map(f=>f.file);
  $('delete-file-list').replaceChildren(...state.deleteFiles.map(file=>el('li','mono',file)));
  if(!result.failed.length)$('delete-dialog').close();
  else{$('delete-error').textContent=result.failed.map(f=>f.file+'：'+f.error).join('；');$('delete-error').hidden=false;}
  tell(`已删除 ${result.deleted.length} 个文件${result.failed.length?'，'+result.failed.length+' 个未删除，请查看提示。':'。'}`,!!result.failed.length);
  await refreshFiles();
 }catch(error){$('delete-error').textContent=error.message;$('delete-error').hidden=false;tell(error.message,true);}
 finally{state.deleting=false;$('delete-cancel').disabled=false;$('delete-confirm').textContent='确认删除';updateSelected();}
};
function fmtCount(n){try{return BigInt(n??0).toLocaleString('zh-CN');}catch{return String(n??0);}}
function fmtBytes(n){return n>=1024*1024?(n/1024/1024).toFixed(1)+' MiB':n>=1024?(n/1024).toFixed(1)+' KiB':(n||0)+' B';}
function updateSelected(){$('selected-count').textContent=state.selectedFiles.size?'已选 '+state.selectedFiles.size+' 个文件':'勾选 2–8 个文件进行对比';$('compare-selected').disabled=state.busy||state.deleting||state.selectedFiles.size<2||state.selectedFiles.size>8||state.files.some(f=>f.error&&state.selectedFiles.has(f.file));$('count-compare').disabled=$('compare-selected').disabled;const blocked=state.busy||!!state.uploading||!!state.deleting;$('delete-selected').disabled=blocked||!state.selectedFiles.size||state.selectedFiles.size>100;document.querySelectorAll('.file-delete').forEach(b=>b.disabled=blocked);$('delete-confirm').disabled=blocked;}
function renderFiles(){const list=$('file-list');list.replaceChildren();if(!state.files.length){const empty=el('div','empty-state');empty.innerHTML='<svg viewBox="0 0 48 48"><path d="M7 13h14l5 5h15v22H7zM7 13V8h17l5 5M18 27h12M24 21v12"/></svg>';empty.append(el('h3','','还没有扫描结果'),el('p','','完成一次扫描，结果会自动保存在这里。也可以导入已有的文本指针链。'));list.append(empty);}for(const f of state.files){const row=el('div','file-row'),check=document.createElement('input');check.type='checkbox';check.setAttribute('aria-label','选择 '+f.file);check.checked=state.selectedFiles.has(f.file);check.onchange=()=>{check.checked?state.selectedFiles.add(f.file):state.selectedFiles.delete(f.file);updateSelected();};const info=el('div');info.append(el('b','',f.file),el('small','',(f.error||[kindLabels[f.kind]||'链文件',f.created_at?new Date(f.created_at*1000).toLocaleString('zh-CN'):'',fmtBytes(f.bytes)].filter(Boolean).join(' · '))));const count=el('div','file-count-cell',f.count_known===false?'未统计':fmtCount(f.count_text??f.count));count.append(el('small','','条指针链'));const badge=el('span','badge '+(f.complete?'success':'partial'),f.complete?'完整':'不完整');const open=el('button','text-button','查看 →');open.disabled=!!f.error;open.onclick=guard(()=>openResult(f.file));const actions=el('div','file-actions'),del=el('button','button danger file-delete','删除');del.setAttribute('aria-label','删除 '+f.file);del.onclick=()=>confirmDelete([f.file]);actions.append(open,del);row.append(check,info,count,badge,actions);list.append(row);}updateSelected();}
async function openResult(file,p=0){
 const data=await api('preview?file='+encodeURIComponent(file)+'&page='+p+'&graph_memory_mb='+num('graph-memory-mb'));
 state.resultFile=file;state.resultPage=p;$('result-detail').hidden=false;$('result-title').textContent=file;
 const m=data.metadata,textFile=file.endsWith('.txt'),known=m.count_known!==false;
 $('result-meta').textContent=`${known?fmtCount(m.count_text??m.count)+' 条链':'链数待统计'} · ${m.complete?'完整结果':'不完整：'+(reasons[m.reason]||m.reason||'未知原因')}`;
 $('download-result').textContent=textFile?'下载文本':'下载二进制';$('export-result').hidden=textFile;$('format-result').hidden=textFile;
 const list=$('chain-list');list.replaceChildren();
 if(!data.rows.length)list.append(el('p','help-text','这份文件中没有指针链。请查看任务日志、读取覆盖和扫描参数。'));
 for(const c of data.rows){const row=el('div','chain-row'),code=el('code','',c.text),button=el('button','text-button','调试这条链 ↗');button.onclick=()=>{$('trace-chains').value=c.text;$('bits').value=c.bits;$('mask').value=c.mask;$('trace-source').value=$('source').value;page('trace');};row.append(code,button);list.append(row);}
 $('prev-page').disabled=p===0;$('next-page').disabled=known?(p+1)*50>=m.count:data.rows.length<50;
 $('page-info').textContent=known?`第 ${p+1} / ${Math.max(1,Math.ceil(m.count/50))} 页`:`第 ${p+1} 页`;
 page('results');
}
function syncFilterTarget(){
 if(state.target){$('filter-pid').value=state.target.pid;$('filter-target').textContent='已连接';$('filter-target').className='badge success';$('filter-process-name').textContent=`${state.target.name} · PID ${state.target.pid}`;}
 else{$('filter-target').textContent='未连接';$('filter-target').className='badge neutral';}
 $('filter-reader').value=$('reader').value;$('filter-bits').value=$('bits').value;
}
function renderFilterFiles(){
 const select=$('filter-file'),previous=select.value;select.replaceChildren(el('option','','请选择一份链文件'));select.firstChild.value='';
 for(const file of state.files){if(file.error)continue;const option=el('option','',`${file.file} · ${kindLabels[file.kind]||'链文件'}`);option.value=file.file;select.append(option);}
 if([...select.options].some(option=>option.value===previous))select.value=previous;
}
function openFilter(file){
 page('filter');if(file){$('filter-local-file').value='';state.filterUploaded=null;$('filter-file').value=file;}
 $('filter-error').hidden=true;$('filter-address').focus();
}
function renderCompareTask(t){
 if(t.kind==='compare'||t.kind==='count')state.compareTask=t;
 const task=state.compareTask;if(!task)return;
 const result=task.result||{},running=task.status==='running';
 $('compare-task-panel').hidden=false;$('compare-task-badge').textContent=statusNames[task.status]||task.status;
 $('compare-task-badge').className='badge '+(task.status==='success'?'success':task.status);
 $('compare-task-message').textContent=task.error||(running?(task.progress?.message||'正在比较所选文件…'):result.file?`已保存对比结果：${result.file}${result.complete?'':' · '+(reasons[result.reason]||result.reason)}`:result.complete?'共同链条统计完成':reasons[result.reason]||result.reason||'任务未完成');
 $('compare-task-count').textContent=`共有 ${fmtCount(result.count_text??result.count??task.progress?.result_count??0)} 条链`;
 $('compare-cancel').hidden=!running;$('compare-view-output').hidden=!result.file;
}
function renderFilterTask(t){
 $('filter-submit').disabled=state.busy||!!state.uploading;
 if(t.kind==='filter')state.filterTask=t;
 const task=state.filterTask;if(!task)return;
 const result=task.result||{},running=task.status==='running';
 $('filter-task-panel').hidden=false;$('filter-task-badge').textContent=statusNames[task.status]||task.status;
 $('filter-task-badge').className='badge '+(task.status==='success'?'success':task.status);
 $('filter-task-message').textContent=task.error||(running?(task.progress?.message||'正在加载链文件并过滤…'):result.file?`已保存新文件：${result.file}${result.complete?'':' · '+(reasons[result.reason]||result.reason)}`:'未生成文件');
 $('filter-task-count').textContent=`保留 ${fmtCount(result.count_text??result.count??task.progress?.result_count??0)} 条链`;
 $('filter-cancel').hidden=!running;$('filter-view-output').hidden=!result.file;$('filter-download-output').hidden=!result.file;
}
async function startTask(request){if(state.busy)throw Error('已有任务正在运行。');clearNotice();state.epoch++;state.submitting=true;state.expectedTask='';if(request.kind==='trace')$('trace-output').replaceChildren();if(request.kind==='backend-status')$('backend-output').textContent='正在检测当前读取器…';if(request.kind==='read-memory'){$('memory-values').replaceChildren();$('memory-output').textContent='正在读取…';}renderTask({status:'running',kind:request.kind,events:[]});try{const accepted=await api('task',request);state.expectedTask=accepted.id;state.submitting=false;state.seenTask='';await poll();}catch(e){state.submitting=false;renderTask({status:'error',error:e.message,events:[]});throw e;}}
function renderTask(t){state.task=t;state.busy=t.status==='running';renderFilterTask(t);renderCompareTask(t);$('start-scan').disabled=state.busy;$('demo-btn').disabled=state.busy;$('demo-link').disabled=state.busy;$('cancel-task').hidden=!state.busy;$('open-task-result').hidden=!(t.result&&t.result.file);$('open-task-result').textContent=t.result?.kind==='format'?'下载文本文件 →':'查看本次结果 →';$('task-badge').textContent=statusNames[t.status]||t.status;$('task-badge').className='badge '+(t.status==='idle'?'neutral':t.status);updateSelected();syncDeletedOutputs();if(t.status==='idle')return;const p=t.progress||{},r=t.result||{};$('task-symbol').hidden=true;$('task-metrics').hidden=false;const count=r.count_text??r.count??p.result_count_text??p.result_count??0;$('task-count').textContent=fmtCount(count);$('task-time').textContent=((r.elapsed_ms??p.elapsed_ms??0)/1000).toFixed(1)+'s';$('task-title').textContent=state.busy?(p.message||'准备执行任务'):t.status==='success'?'任务已完成':t.status==='partial'?'已保存部分结果':t.status==='cancelled'?'任务已停止':'任务未完成';$('task-message').textContent=t.error||(t.status==='partial'?(reasons[r.reason]||r.reason):r.file?`结果已保存：${r.file}`:state.busy?'正在处理，进度来自扫描核心。':t.status==='success'?'执行完成，可查看结果。':'未发布完整结果。');const progress=$('progress-track');progress.hidden=!state.busy;if(state.busy){$('progress-bar').style.width=p.phase==='collect'&&p.total_bytes?Math.min(100,(p.read_bytes||0)/p.total_bytes*100)+'%':'0%';progress.setAttribute('aria-label',p.phase==='collect'?'内存采集进度':'搜索阶段，总工作量未知');}
$('task-logs').textContent=(t.events||[]).map(e=>`[${(e.elapsed_ms/1000).toFixed(2)}s] ${e.message}${e.pointers!==undefined?' · 指针 '+e.pointers:''}${e.result_count!==undefined?' · 链 '+e.result_count:''}${e.failed_bytes?' · 失败字节 '+e.failed_bytes:''}`).join('\n')+(t.error?'\n错误：'+t.error:'');}
function renderTrace(traces){const out=$('trace-output');out.replaceChildren();for(const t of traces){const card=el('section','trace-card');card.append(el('span','badge '+(t.ok?'success':'error'),t.ok?'解析成功':'解析失败'),el('code','',t.chain));if(t.base)card.append(el('p','help-text',`根地址 ${t.base} → 起始读取地址 ${t.root_address}`));for(const s of t.steps){const step=el('div','trace-step');step.append(el('b','',`第 ${s.level} 层`),el('small','',`读取 ${s.address} · 偏移 ${s.offset}`),el('code','',s.ok?`${s.pointer} → ${s.next}`:s.error));card.append(step);}const final=el('div','trace-final',t.ok?`最终地址 ${t.address}　${t.value_readable?`int32: ${t.int32} · float32: ${t.float32}`:'该地址处的值不可读'}`:t.error);card.append(final);out.append(card);}}
async function poll(){const epoch=state.epoch;if(state.submitting)return;try{const t=await api('task');if(epoch!==state.epoch||state.submitting||(state.expectedTask&&t.id!==state.expectedTask))return;renderTask(t);$('connection').textContent='引擎已连接';$('connection-dot').style.background='#6caa79';if(t.status!=='running'&&t.status!=='idle'&&state.seenTask!==t.id){state.seenTask=t.id;await refreshFiles();const r=t.result||{};if(t.error)tell(t.error,true);else if(r.kind==='trace'){renderTrace(r.traces);}else if(r.kind==='reader-test'){ $('backend-output').textContent=JSON.stringify(r.reader_info,null,2);tell(`读取测试完成：${r.reader} 在 ${r.address} 读取 ${r.bytes_read}/${r.requested} 字节 · ${r.reader_info.transport}。${r.complete?'':'存在短读。'}`); }else if(r.kind==='backend-status'){ $('backend-output').textContent=JSON.stringify(r.reader_info||{error:r.error,runtime:r.runtime},null,2);tell(r.available?'读取通道已打开；请再使用目标地址测试实际读取。':r.error,!r.available); }else if(r.kind==='read-memory'){ $('memory-output').textContent=r.dump;$('memory-values').replaceChildren();for(const [type,value] of Object.entries(r.values)){const cell=el('div');cell.append(el('small','',type),el('code','',String(value)));$('memory-values').append(cell);}tell(`读取 ${r.bytes_read}/${r.requested} 字节 · ${r.reader_info.transport}`); }else if(r.kind==='count')tell(`共同链数：${r.count}${r.complete?'':'（部分结果）'}`);else if(r.kind==='format'&&r.file){try{await downloadFormatted(r.file);tell(`${statusNames[t.status]}：已生成 ${r.file}，已交给浏览器下载${r.complete?'':'。'+(reasons[r.reason]||r.reason)}`);}catch(e){tell(`文本已生成，但下载失败：${e.message}`,true);}}else if(r.file)tell(`${statusNames[t.status]}：${r.count} 条链，保存为 ${r.file}${r.complete?'':'。'+(reasons[r.reason]||r.reason)}`);}}catch(e){$('connection').textContent='连接已断开';$('connection-dot').style.background='#d98279';if(state.busy)tell('与本地引擎的连接已断开，请检查运行程序的终端。',true);}}
async function nativeDownload(endpoint,file){
 const budget=num('graph-memory-mb');
 const grant=await api('download-ticket',{endpoint,file,graph_memory_mb:budget});
 const link=document.createElement('a');
 link.href='/api/'+endpoint+'?'+new URLSearchParams({file,ticket:grant.ticket,graph_memory_mb:budget});
 link.download=endpoint==='export'?file.replace(/\.cptr$/,'.txt'):file;
 document.body.append(link);link.click();link.remove();
}
async function download(text=false){if(!state.resultFile)return;await nativeDownload(state.resultFile.endsWith('.txt')?'text-download':text?'export':'download',state.resultFile);tell('已交给浏览器下载；大文件会逐块传输，可在浏览器下载列表查看。');}
async function downloadFormatted(file){await nativeDownload('text-download',file);}
async function uploadFile(file,progress=$('import-progress')){
 const session=await api('upload/start',{name:file.name,bytes:file.size});
 try{
  for(let offset=0;offset<file.size;offset+=session.chunk_bytes){
   if(state.uploadCancelled)throw Error('已取消文件上传。');
   const response=await fetch('/api/upload/chunk?'+new URLSearchParams({id:session.id,offset}),{method:'POST',headers:{'X-CSCAN-Token':token,'Content-Type':'application/octet-stream'},body:file.slice(offset,offset+session.chunk_bytes)});
   if(!response.ok){const error=await response.json();throw Error(error.error||'上传失败');}
   progress.textContent=`正在上传 ${Math.min(100,Math.round((offset+session.chunk_bytes)/file.size*100))}% · ${fmtBytes(file.size)}`;
  }
  if(state.uploadCancelled)throw Error('已取消文件上传。');
  const finished=await api('upload/finish',{id:session.id});progress.textContent=`已上传 ${file.name} · ${fmtBytes(file.size)}`;return finished;
 }catch(error){await api('upload/cancel',{id:session.id}).catch(()=>{});throw error;}
}
function savePrefs(){const data={};for(const id of ['depth','offset','bits','reader','limit','memory-mb','graph-memory-mb','threads','timeout','mask','layer-offsets'])data[id]=$(id).value;for(const id of ['negative','step4','nonread'])data[id]=$(id).checked;try{localStorage.setItem('cscan-preferences-v1',JSON.stringify(data));}catch{}}
function restorePrefs(){try{const p=JSON.parse(localStorage.getItem('cscan-preferences-v1')||'{}');for(const[id,v]of Object.entries(p))if($(id)){if(typeof v==='boolean')$(id).checked=v;else $(id).value=v;}}catch{}}
document.querySelectorAll('[data-page]').forEach(b=>b.onclick=()=>page(b.dataset.page));window.addEventListener('hashchange',()=>page(location.hash.slice(1)));
$('connect-target').onclick=guard(async()=>{try{await connect(num('pid'));}catch(e){await diagnosePid(num('pid'));throw e;}});$('diagnose-pid').onclick=guard(()=>diagnosePid(num('pid')));$('process-probe').onclick=guard(()=>diagnosePid(Number($('process-query').value.trim())));$('process-open').onclick=guard(async()=>{$('process-query').value=$('process-search').value;$('process-dialog').showModal();await refreshProcesses();});$('process-query').oninput=renderProcesses;
$('demo-btn').onclick=guard(demo);$('demo-link').onclick=guard(demo);$('mode-scan').onclick=()=>setMode('scan');$('mode-relation').onclick=()=>setMode('relation');
$('reader').onchange=()=>{savePrefs();updateSummary();};document.querySelectorAll('[data-reader]').forEach(b=>b.onclick=()=>{$('reader').value=b.dataset.reader;savePrefs();updateSummary();tell('已选择 '+readers[b.dataset.reader][0]+'。回到工作台连接进程后测试读取。');});
$('scan-form').onsubmit=guard(async(e)=>{e.preventDefault();savePrefs();await startTask(scanConfig());});$('offset').oninput=()=>{try{let n=BigInt($('offset').value);$('offset-hint').textContent=n.toString()+' 字节 / 0x'+n.toString(16).toUpperCase();}catch{$('offset-hint').textContent='默认十进制，十六进制需加 0x';}};
$('choose-modules').onclick=guard(async()=>{if(!state.target)throw Error('请先连接目标进程。');state.draftModules=new Set(state.selectedModules.length?state.selectedModules:state.modules.map(m=>m.id));$('module-query').value='';renderModules();$('module-dialog').showModal();});$('module-query').oninput=renderModules;$('module-all').onclick=()=>{state.draftModules=new Set(state.modules.map(m=>m.id));renderModules();};$('module-none').onclick=()=>{state.draftModules.clear();renderModules();};$('module-save').onclick=guard(()=>{if(!state.draftModules.size)throw Error('至少选择一个根模块。');state.selectedModules=state.draftModules.size===state.modules.length?[]:[...state.draftModules];$('module-dialog').close();updateSummary();});
$('backend-test').onclick=guard(()=>startTask({kind:'backend-status',reader:$('reader').value}));$('memory-read').onclick=guard(()=>startTask({...base(),kind:'read-memory',addresses:$('memory-address').value.trim(),size:num('memory-size')}));
$('reader-test').onclick=guard(()=>startTask({...base(),kind:'reader-test',addresses:$('addresses').value.trim()}));$('cancel-task').onclick=guard(async()=>{await api('cancel',{});$('cancel-task').disabled=true;$('cancel-task').textContent='正在停止…';});$('open-task-result').onclick=guard(()=>state.task.result.kind==='format'?downloadFormatted(state.task.result.file):openResult(state.task.result.file));
$('compare-selected').onclick=guard(async()=>{await startTask({kind:'compare',files:[...state.selectedFiles],timeout:num('timeout'),graph_memory_mb:num('graph-memory-mb'),limit:num('limit')});});$('count-compare').onclick=guard(async()=>{await startTask({kind:'count',files:[...state.selectedFiles],timeout:num('timeout'),graph_memory_mb:num('graph-memory-mb')});});
$('close-result').onclick=()=>{$('result-detail').hidden=true;};$('prev-page').onclick=guard(()=>openResult(state.resultFile,state.resultPage-1));$('next-page').onclick=guard(()=>openResult(state.resultFile,state.resultPage+1));$('download-result').onclick=guard(()=>download());$('export-result').onclick=guard(()=>download(true));$('format-result').onclick=guard(async()=>{if(!state.resultFile)throw Error('请先打开一份结果。');await startTask({kind:'format',file:state.resultFile,graph_memory_mb:num('graph-memory-mb'),bits:num('bits'),mask:$('mask').value,timeout:num('timeout')});page('scan');});
$('filter-result').onclick=()=>openFilter(state.resultFile);$('run-trace').onclick=guard(()=>startTask({...base(),kind:'trace',chains:$('trace-chains').value,source:$('trace-source').value.trim()}));
$('import-open').onclick=()=>{$('import-dialog').showModal();};
$('import-file').onchange=()=>{const file=$('import-file').files[0];$('import-progress').textContent=file?`已选择 ${file.name} · ${fmtBytes(file.size)}；将分块上传。`:'';$('import-text').disabled=!!file;};
$('import-cancel').onclick=()=>{state.uploadCancelled=true;};
$('import-submit').onclick=guard(async()=>{
 if(state.busy||state.uploading)throw Error('请等待当前任务结束。');
 state.uploading=true;state.uploadCancelled=false;$('import-submit').disabled=true;$('import-cancel').hidden=false;
 $('import-dialog').setAttribute('aria-busy','true');
 try{
  const file=$('import-file').files[0];
  const request={kind:'import',bits:num('bits'),mask:$('mask').value,graph_memory_mb:num('graph-memory-mb'),timeout:num('timeout')};
  if(file)Object.assign(request,await uploadFile(file));else request.text=$('import-text').value;
  await startTask(request);$('import-dialog').close();$('import-file').value='';$('import-text').disabled=false;page('scan');
 }finally{state.uploading=false;$('import-submit').disabled=false;$('import-cancel').hidden=true;$('import-dialog').removeAttribute('aria-busy');}
});
$('import-dialog').addEventListener('close',()=>{if(state.uploading)state.uploadCancelled=true;});
document.querySelectorAll('.close-dialog').forEach(b=>b.onclick=()=>b.closest('dialog').close());$('refresh-all').onclick=guard(async()=>{await Promise.all([refreshFiles(),refreshProcesses()]);tell('进程列表与结果已刷新。');});
$('filter-reader').innerHTML=$('reader').innerHTML;
$('filter-reader').onchange=()=>{$('reader').value=$('filter-reader').value;savePrefs();updateSummary();};
$('filter-bits').onchange=()=>{$('bits').value=$('filter-bits').value;};
$('filter-connect').onclick=guard(()=>connect(num('filter-pid')));
$('filter-process-open').onclick=guard(async()=>{$('process-query').value='';$('process-dialog').showModal();await refreshProcesses();});
$('filter-file').onchange=()=>{if($('filter-file').value){$('filter-local-file').value='';state.filterUploaded=null;}};
$('filter-local-file').onchange=()=>{if($('filter-local-file').files[0])$('filter-file').value='';state.filterUploaded=null;};
$('filter-output-format').onchange=()=>{const extension=$('filter-output-format').value==='text'?'.txt':'.cptr';$('filter-output-name').placeholder=`例如 filtered${extension}；留空自动命名`;$('filter-output-name').value=$('filter-output-name').value.replace(/\.(cptr|txt)$/i,extension);};
$('filter-form').onsubmit=async(event)=>{
 event.preventDefault();$('filter-error').hidden=true;
 try{
  if(state.busy||state.uploading)throw Error('已有任务或文件上传正在进行，请稍后再试。');
  if(!state.target||num('filter-pid')!==state.target.pid)throw Error('请先连接本次目标进程。');
  const address=$('filter-address').value.trim();if(!address)throw Error('请填写本次确定的十六进制绝对地址。');
  const local=$('filter-local-file').files[0];let file=$('filter-file').value;
  if(!file&&!local)throw Error('请选择已保存的链文件，或从设备选择文件。');
  if(local){
   if(state.filterUploaded?.source===local)file=state.filterUploaded.file;
   else{
    state.uploading=true;state.uploadCancelled=false;$('filter-submit').disabled=true;$('filter-upload-cancel').hidden=false;
    const uploaded=await uploadFile(local,$('filter-upload-progress'));file=uploaded.file;state.filterUploaded={source:local,file};
   }
  }
  state.uploading=false;$('filter-upload-cancel').hidden=true;
  const format=$('filter-output-format').value,ext=format==='text'?'.txt':'.cptr';let output=$('filter-output-name').value.trim();if(output&&!/\.(cptr|txt)$/i.test(output))output+=ext;
  await startTask({...base(),kind:'filter',file,addresses:address,source:$('filter-source').value.trim(),reader:$('filter-reader').value,bits:num('filter-bits'),limit:num('filter-limit'),output_format:format,...(output?{output}:{})});
  $('filter-task-panel').scrollIntoView({behavior:'auto',block:'nearest'});
 }catch(error){$('filter-error').textContent=error.message;$('filter-error').hidden=false;}
 finally{state.uploading=false;$('filter-upload-cancel').hidden=true;$('filter-submit').disabled=state.busy;}
};
$('filter-upload-cancel').onclick=()=>{state.uploadCancelled=true;};
$('compare-cancel').onclick=guard(()=>api('cancel',{}));
$('compare-view-output').onclick=guard(()=>openResult(state.compareTask.result.file));
$('filter-cancel').onclick=guard(()=>api('cancel',{}));
$('filter-view-output').onclick=guard(()=>openResult(state.filterTask.result.file));
$('filter-download-output').onclick=guard(()=>nativeDownload(state.filterTask.result.file.endsWith('.txt')?'text-download':'download',state.filterTask.result.file));
async function init(){restorePrefs();page(location.hash.slice(1)||'scan');updateSummary();try{const status=await api('status');$('data-location').textContent=status.data_dir;document.querySelectorAll('.output-directory').forEach(node=>node.textContent=status.data_dir);$('engine-version').textContent=status.version;renderRuntime(status.runtime);await refreshFiles();await poll();}catch(e){tell(e.message,true);}setInterval(async()=>{if(!document.hidden){await poll();if(!state.busy){$('cancel-task').disabled=false;$('cancel-task').textContent='停止当前任务';}}},1000);}
init();
