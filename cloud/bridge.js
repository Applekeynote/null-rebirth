'use strict';
const $ = id => document.getElementById(id);
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const PHASE = {
 NORMAL:['normal',0,'ALL SYSTEMS NOMINAL','The disposable workload passed its baseline checks.'],
 ANOMALY:['anomaly',1,'ANOMALY DETECTED','Independent probes found a failing service condition.'],
 WARNING:['warning',2,'CONTAINMENT ACTIVE','New work is held while PATCH investigates the evidence.'],
 DIAGNOSING:['warning',2,'AI DIAGNOSIS REQUESTED','PATCH is asking Amazon Nova to select a scoped runbook.'],
 REPAIR_READY:['anomaly',2,'REPAIR PLAN VALIDATED','The AI-selected runbook matches the observed failure.'],
 REPAIRING:['repair',3,'REPAIR IN PROGRESS','The approved change is applied to the persisted lab workload.'],
 VERIFYING:['verify',4,'VERIFYING RECOVERY','Independent probes and KMS attestation must agree.'],
 NORMALIZED:['normalized',5,'SYSTEM NORMALIZED','20 checks passed. The current-state signature is verified.'],
 REPORTING:['normalized',5,'SYSTEM NORMALIZED','LOG is composing the verified recovery report.'],
 COMPLETE:['normalized',5,'SYSTEM NORMALIZED','Recovery verified. Evidence sealed. Report delivered.'],
 BLOCKED:['blocked',2,'DIAGNOSIS PAUSED','No verified normalization is available.'],
};
const TRACE = {
 NORMAL:['BRIDGE','Created an isolated, healthy workload.'], ANOMALY:['WITNESS','Injected the selected fault; independent checks detected it.'],
 WARNING:['CONTROL','Contained the incident. Awaiting a bounded repair plan.'], DIAGNOSING:['PATCH','Requested an evidence-based diagnosis from Amazon Nova Micro.'],
 REPAIR_READY:['PATCH','Validated the model-selected runbook against current evidence.'], REPAIRING:['PATCH','Applied the repair with an atomic state comparison.'],
 VERIFYING:['VERIFIER','Re-probed the repaired workload with independent challenges.'], NORMALIZED:['COMMIT','Verified the KMS signature and released normalization atomically.'],
 REPORTING:['LOG','Requested a separate report from verified recovery facts.'], COMPLETE:['LOG','Recovery record complete.'], BLOCKED:['CONTROL','Stopped safely; no repair or normalization is assumed.'],
};
let incidents=[], selected=null, filter='SECURITY', busy=false, paused=false, state=null, snapshots=[], resume=false, replaying=false;
let catalogPage=0, catalogSize=6, commsPage=0, commsSize=3, commsTab='dialogue', dialogue=[], events=[];
const isSecurity=()=>selected?.mode==='containment';
const totalChecks=s=>s?.verification?.checks_total??s?.probe?.total??s?.observed?.total??25;
const reduced = $('reduce-motion');
reduced.checked = matchMedia('(prefers-reduced-motion: reduce)').matches;
function motion(){document.body.classList.toggle('reduced-motion',reduced.checked);}
reduced.addEventListener('change',motion);motion();
function text(id, value){$(id).textContent=value;}
function readout(id, value, detail){const el=$(id);el.replaceChildren(document.createTextNode(value));const s=document.createElement('small');s.textContent=detail;el.append(s);}
async function request(path, body){
 const response=await fetch(path,{method:body===undefined?'GET':'POST',headers:{'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body),cache:'no-store'});
 if(response.status===401){sessionStorage.removeItem('nr-heal-run');location.replace('/');throw Error('Review session expired. Sign in again.');}
 if(response.status===410)throw Error('The review period has closed.');
 let data;try{data=await response.json();}catch{throw Error('The server returned an unreadable response.');}
 if(!response.ok)throw Error(data.error==='HEAL_SESSION_EXPIRED'?'This lab session has expired. Start a new incident.':'The operation could not complete. Reconnect to resume safely.');
 return data;
}
function controls(){
 $('run').disabled=busy||!selected;
 $('run').replaceChildren(document.createTextNode(busy?(replaying?'REPLAYING':'OPERATORS AT WORK'):resume?'RESUME INCIDENT':state?'RUN AGAIN':'RUN INCIDENT'));
 const arrow=document.createElement('span');arrow.textContent='↗';$('run').append(arrow);
 $('pause').disabled=!busy;$('replay').disabled=busy||snapshots.length<2;
 document.querySelectorAll('.incident-button').forEach(b=>b.disabled=busy);
 $('search').disabled=busy;document.querySelectorAll('[data-filter]').forEach(b=>b.disabled=busy);
}
function list(){
 const q=$('search').value.trim().toLowerCase();
 const shown=incidents.filter(i=>(filter==='ALL'||i.category===filter)&&`${i.title} ${i.company} ${i.date}`.toLowerCase().includes(q));
 const frag=document.createDocumentFragment();
 const pages=Math.max(1,Math.ceil(shown.length/catalogSize));catalogPage=Math.min(catalogPage,pages-1);
 for(const i of shown.slice(catalogPage*catalogSize,(catalogPage+1)*catalogSize)){
  const b=document.createElement('button');b.className='incident-button'+(selected?.id===i.id?' selected':'');b.dataset.incident=i.id;b.setAttribute('aria-pressed',String(selected?.id===i.id));
  const num=document.createElement('span');num.className='number';num.textContent=String(incidents.indexOf(i)+1).padStart(2,'0');
  const copy=document.createElement('span'),title=document.createElement('strong'),origin=document.createElement('small');title.textContent=i.title;origin.textContent=`${i.company.toUpperCase()} / ${i.date.slice(0,4)}`;copy.append(title,origin);
  const a=document.createElement('span');a.className='arrow';a.textContent='↗';b.append(num,copy,a);b.onclick=()=>select(i);frag.append(b);
 }
 $('incidents').replaceChildren(frag);text('catalog-count',String(shown.length).padStart(2,'0'));$('empty-list').hidden=shown.length>0;
 text('catalog-page',`${catalogPage+1} / ${pages}`);$('catalog-prev').disabled=catalogPage===0;$('catalog-next').disabled=catalogPage===pages-1;
 document.querySelectorAll('[data-filter]').forEach(b=>b.classList.toggle('selected',b.dataset.filter===filter));controls();
}
function select(i,keep=false){
 if(busy)return;selected=i;if(filter!=='ALL'&&i.category!==filter){filter='ALL';catalogPage=Math.floor(incidents.indexOf(i)/catalogSize);}
 text('origin-line',`${i.company.toUpperCase()} / ${i.date} / ${isSecurity()?'CONTAINMENT':'RECOVERY'}`);text('mission-title',i.title);text('mission-summary',i.summary);$('source-link').href=i.source;
 document.body.dataset.mode=isSecurity()?'containment':'recovery';
 for(const [step,label] of [[3,isSecurity()?'CONTAIN':'REPAIR'],[5,isSecurity()?'CONTAINED':'NORMALIZED']])document.querySelector(`[data-step="${step}"]`).lastChild.textContent=label;
 const target={EDGE:['17%','19%'],IDENTITY:['46%','5%'],NETWORK:['73%','19%'],COMPUTE:['16%','53%'],DATA:['72%','53%']}[i.component];
 document.body.style.setProperty('--patch-x',target[0]);document.body.style.setProperty('--patch-y',target[1]);
 if(!keep){state=null;snapshots=[];resume=false;sessionStorage.removeItem('nr-heal-run');reset();}
 list();positionCrew();
}
function reset(){
 document.body.dataset.stage='normal';text('phase-code','STATE / 00');text('scene-status','ALL SYSTEMS NOMINAL');text('scene-detail','Select an incident. Let the operators work.');text('run-short','AWAITING INCIDENT');text('patch-mode','STANDBY');text('log-mode','LISTENING');
 text('patch-speech','I find the fault, choose an approved fix, and get to work.');text('log-speech','I keep the evidence. When the checks pass, you get the report.');text('runbook-name','AWAITING DIAGNOSIS');text('report-status','REPORT PENDING');text('report-engine','VERIFIED RESULTS ONLY');text('trace-state','STANDBY');
 readout('check-count','—','/25');readout('proof-state','PENDING','KMS / ECDSA');readout('authority','SCOPED','LAB ONLY');$('evidence').disabled=true;
 document.querySelectorAll('.system-node').forEach(n=>{n.classList.remove('fault','fixed');n.querySelector('b').textContent='READY';});
 document.querySelectorAll('[data-step]').forEach((n,k)=>{n.classList.toggle('active',k===0);n.classList.remove('done');});
 $('trace').replaceChildren();
 dialogue=['PATCH','LOG'].map(speaker=>({speaker,text:$(speaker==='PATCH'?'patch-speech':'log-speech').textContent,at:Math.floor(Date.now()/1000),phase:'STANDBY',revision:-1}));events=[];commsPage=0;renderComms();positionCrew();
}
function render(s, transient=false){
 const total=totalChecks(s);
 const verified=s.verification?.healthy===true&&s.verification?.kms_signature_verified===true&&s.verification?.checks_passed===total;
 let info=PHASE[s.phase]||PHASE.BLOCKED;
 if(isSecurity())info=({ANOMALY:['anomaly',1,'UNAUTHORIZED ACCESS DETECTED','Independent probes observed synthetic records crossing the lab boundary.'],WARNING:['warning',2,'EVIDENCE PRESERVED','Containment is pending an approved action.'],DIAGNOSING:['warning',2,'AI CONTAINMENT ANALYSIS','PATCH is selecting a bounded containment runbook.'],REPAIR_READY:['anomaly',2,'CONTAINMENT PLAN VALIDATED','The selected action matches the observed access path.'],REPAIRING:['repair',3,'CONTAINMENT IN PROGRESS','PATCH applied the access policy. Independent denial tests follow.'],VERIFYING:['verify',4,'VERIFYING CONTAINMENT','Re-test unauthorized requests, legitimate reads, and evidence integrity.'],NORMALIZED:['normalized',5,'THREAT CONTAINED','Unauthorized lab reads denied. Evidence sealed.'],REPORTING:['normalized',5,'THREAT CONTAINED','LOG is composing the verified containment report.'],COMPLETE:['normalized',5,'THREAT CONTAINED','Denied access verified. Evidence preserved. Report delivered.']})[s.phase]||info;
 if(['NORMALIZED','REPORTING','COMPLETE'].includes(s.phase)&&!verified)info=PHASE.BLOCKED;
 const [stage,index,title,description]=info;
 const detail=verified&&!isSecurity()&&s.phase==='NORMALIZED'?`${total} checks passed. The current-state signature is verified.`:description;
 document.body.dataset.stage=stage;text('phase-code',`STATE / ${String(index).padStart(2,'0')}`);text('scene-status',title);text('scene-detail',detail);text('announcement',title+'. '+detail);
 text('run-short',`${replaying?'RECORDED / ':''}${s.run_id.slice(0,16).toUpperCase()}`);text('trace-state',s.phase.replaceAll('_',' '));
 document.querySelectorAll('[data-step]').forEach(n=>{const k=Number(n.dataset.step);n.classList.toggle('active',k===index);n.classList.toggle('done',k<index);});
 const repaired=['REPAIRING','VERIFYING','NORMALIZED','REPORTING','COMPLETE'].includes(s.phase);
 document.querySelectorAll('.system-node').forEach(n=>{const affected=n.dataset.component===selected.component&&index>0;n.classList.toggle('fault',affected&&!repaired);n.classList.toggle('fixed',affected&&repaired);n.querySelector('b').textContent=affected?(verified?'VERIFIED':repaired?'RECHECK':'FAULT'):'READY';});
 const count=verified?total:(s.probe?.passed_count??(repaired?undefined:s.observed?.passed_count));readout('check-count',count===undefined?'—':String(count),'/'+total);readout('proof-state',verified?'VERIFIED':'PENDING','KMS / ECDSA');readout('authority',s.delta?'CONSUMED':'SCOPED','LAB ONLY');
 const patchMode={NORMAL:'STANDBY',ANOMALY:'OBSERVING',WARNING:'CONTAINING',DIAGNOSING:'DIAGNOSING',REPAIR_READY:'PLAN READY',REPAIRING:'REPAIRING',VERIFYING:'AWAITING PROOF',NORMALIZED:'FIX VERIFIED',REPORTING:'FIX VERIFIED',COMPLETE:'COMPLETE',BLOCKED:'PAUSED'};
 text('patch-mode',patchMode[s.phase]||'PAUSED');text('log-mode',s.phase==='REPORTING'?'COMPOSING':s.phase==='COMPLETE'?'DELIVERED':s.phase==='VERIFYING'?'CHECKING':'LISTENING');
 let speech=s.plan?.diagnosis||'I am checking the independent evidence before choosing a repair.';
 if(s.phase==='NORMAL')speech='The baseline is clean. I am ready to observe the injected incident.';
 if(s.phase==='DIAGNOSING')speech='I am asking Amazon Nova to diagnose these failed checks and choose an approved runbook.';
 if(s.phase==='REPAIR_READY')speech=`${s.plan.diagnosis} ${s.plan.reason}`;
 if(s.phase==='REPAIRING')speech=`I applied ${s.delta.length} scoped configuration change${s.delta.length===1?'':'s'}. Independent verification comes next.`;
 if(verified)speech=`The approved action is complete. All ${total} checks and the current-state signature passed.`;
 if(s.phase==='BLOCKED'){
  speech=s.error?.startsWith('AI_UNAVAILABLE')?'Amazon Bedrock is unavailable for this account. I have not applied a repair.':'The evidence or repair plan did not pass the safety gate. I stopped the workflow.';
  text('scene-detail',s.error?.startsWith('AI_UNAVAILABLE')?'AI diagnosis unavailable. The fault remains contained.':'Safety gate closed. No normalization is assumed.');
 }
 const messages=s.dialogue||[];
 const last=who=>[...messages].reverse().find(x=>x.speaker===who)?.text;
 if(!transient)speech=last('PATCH')||speech;
 if(transient&&s.phase==='DIAGNOSING')speech=isSecurity()?'I am asking Amazon Nova to select an approved containment runbook.':'I am asking Amazon Nova to diagnose the failure and select an approved runbook.';
 if(transient&&s.phase==='VERIFYING')speech=isSecurity()?'The verifier is testing blocked access, legitimate reads, and evidence integrity.':'The verifier is testing the repaired workload and its current-state signature.';
 text('patch-speech',speech);text('runbook-name',s.plan?.runbook.replaceAll('_',' ')||'AWAITING DIAGNOSIS');
 text('log-speech',last('LOG')||s.report|| (verified?`The independent verifier confirmed ${total} passing checks. I am preparing the record.`:s.phase==='BLOCKED'?'No recovery certificate was released. I recorded the blocked diagnosis.':'I am recording the transitions. I will report success only after independent verification.'));
 text('report-status',s.report?'REPORT DELIVERED':'REPORT PENDING');text('report-engine',s.report_engine==='AMAZON_NOVA_MICRO'?'AMAZON NOVA MICRO':s.report_engine?'VERIFIED TEMPLATE / AI UNAVAILABLE':'VERIFIED RESULTS ONLY');
 const livePage=commsPage>=Math.max(0,Math.ceil((commsTab==='dialogue'?dialogue:events).length/commsSize)-1);
 dialogue=messages.map(x=>({...x}));
 if(transient&&!dialogue.some(x=>x.speaker==='PATCH'&&x.text===speech))dialogue.push({speaker:'PATCH',text:speech,at:s.updated_at,phase:s.phase,revision:s.revision});
 if(!transient){$('evidence').disabled=false;trace(s);}
 if(livePage)commsPage=Math.max(0,Math.ceil((commsTab==='dialogue'?dialogue:events).length/commsSize)-1);
 renderComms();positionCrew();
}
function trace(s){
 events=(s.history||[]).map(h=>{let [speaker,message]=TRACE[h.phase]||TRACE.BLOCKED;if(isSecurity())message=({ANOMALY:'Detected unauthorized synthetic reads.',WARNING:'Preserved access evidence before containment.',REPAIRING:'Applied the scoped containment policy atomically.',VERIFYING:'Re-tested unauthorized and legitimate requests.',NORMALIZED:'Verified denial, preserved evidence, and the KMS signature.'})[h.phase]||message;return {...h,speaker,text:message};});
}
function renderComms(){
 const source=commsTab==='dialogue'?dialogue:events,pages=Math.max(1,Math.ceil(source.length/commsSize));commsPage=Math.min(Math.max(0,commsPage),pages-1);
 const target=$(commsTab==='dialogue'?'conversation':'trace'),frag=document.createDocumentFragment();
 for(const message of source.slice(commsPage*commsSize,(commsPage+1)*commsSize)){const row=document.createElement('p'),who=document.createElement('span'),time=document.createElement('time'),copy=document.createElement('strong');who.textContent=message.speaker;time.textContent=new Date(message.at*1000).toISOString().slice(11,19)+'Z';copy.textContent=message.text;row.append(who,time,copy);if(message.speaker==='LOG')row.className='log-message';frag.append(row);}
 if(!source.length){const p=document.createElement('p');p.className='comms-empty';p.textContent='PATCH and LOG are standing by.';frag.append(p);}
 target.replaceChildren(frag);target.scrollTop=0;
 $('conversation').hidden=commsTab!=='dialogue';$('trace').hidden=commsTab!=='trace';
 $('tab-dialogue').setAttribute('aria-selected',String(commsTab==='dialogue'));$('tab-trace').setAttribute('aria-selected',String(commsTab==='trace'));
 text('comms-page',`${commsPage+1} / ${pages}${commsPage===pages-1?' · LIVE':''}`);$('comms-prev').disabled=commsPage===0;$('comms-next').disabled=commsPage===pages-1;
}
function positionCrew(){
 const scene=$('scene'),w=scene.clientWidth,h=scene.clientHeight,repairing=document.body.dataset.stage==='repair';
 const node=scene.querySelector(`[data-component="${selected?.component||'EDGE'}"]`),cat=scene.querySelector('.patch-sprite');
 const x=repairing&&node?Math.max(3,Math.min(w-cat.clientWidth-3,node.offsetLeft+node.clientWidth-cat.clientWidth/2)):Math.max(6,w*.025);
 const y=repairing&&node?Math.max(3,Math.min(h-cat.clientHeight-24,node.offsetTop-8)):Math.max(4,h*.58);
 scene.style.setProperty('--patch-pos-x',x+'px');scene.style.setProperty('--patch-pos-y',Math.min(y,h-cat.clientHeight-18)+'px');scene.style.setProperty('--log-pos-x',(w-scene.querySelector('.log-sprite').clientWidth-Math.max(8,w*.025))+'px');scene.style.setProperty('--log-pos-y',Math.max(4,h*.58)+'px');
}
function resizeBridge(){
 const next=Math.max(3,Math.min(8,Math.floor($('incidents').clientHeight/64)||3));
 if(next!==catalogSize){const oldStart=catalogPage*catalogSize;catalogSize=next;catalogPage=Math.floor(oldStart/next);if(incidents.length)list();}
 const size=Math.max(2,Math.min(4,Math.floor($('conversation').clientHeight/100)||2));
 if(size!==commsSize){const oldStart=commsPage*commsSize;commsSize=size;commsPage=Math.floor(oldStart/size);renderComms();}
 positionCrew();
}
new ResizeObserver(resizeBridge).observe($('scene'));
$('catalog-prev').onclick=()=>{catalogPage--;list();};$('catalog-next').onclick=()=>{catalogPage++;list();};
$('comms-prev').onclick=()=>{commsPage--;renderComms();};$('comms-next').onclick=()=>{commsPage++;renderComms();};
for(const [id,tab] of [['tab-dialogue','dialogue'],['tab-trace','trace']])$(id).onclick=()=>{commsTab=tab;commsPage=Math.max(0,Math.ceil((tab==='dialogue'?dialogue:events).length/commsSize)-1);renderComms();};
async function waitBeat(ms){let remaining=reduced.checked?100:ms;while(remaining>0||paused){await sleep(100);if(!paused)remaining-=100;}}
function accept(s){state=s;snapshots.push(structuredClone(s));sessionStorage.setItem('nr-heal-run',s.run_id);render(s);}
async function sequence(){
 while(!['COMPLETE','BLOCKED'].includes(state.phase)){
  if(state.phase==='NORMAL'&&state.fault_due_at){while(Date.now()/1000<state.fault_due_at){text('scene-detail','Monitoring · random fault window 2–5 minutes · '+Math.max(0,Math.floor(Date.now()/1000-state.started_at))+'s elapsed');await sleep(1000);}}
  await waitBeat(({NORMAL:900,ANOMALY:1800,WARNING:2600,REPAIR_READY:1800,REPAIRING:3000,NORMALIZED:1300})[state.phase]||900);
  if(state.phase==='WARNING')render({...state,phase:'DIAGNOSING'},true);
  const verifying=state.phase==='REPAIRING';if(verifying)render({...state,phase:'VERIFYING'},true);
  const started=performance.now();const next=await request('/api/heal/step',{run_id:state.run_id,revision:state.revision});
  if(verifying&&!reduced.checked)await sleep(Math.max(0,1900-(performance.now()-started)));
  accept(next);
 }
 resume=false;
}
$('run').onclick=async()=>{
 if(busy||!selected)return;busy=true;paused=false;document.body.classList.remove('paused');controls();
 try{if(!resume){snapshots=[];reset();accept(await request('/api/heal',{scenario:selected.id}));}await sequence();}
 catch(error){
  text('scene-status','CONNECTION PAUSED');text('scene-detail',error.message);document.body.dataset.stage='blocked';text('patch-mode','PAUSED');text('patch-speech','I cannot confirm the latest operation. Reconnect to read the persisted state before continuing.');
  if(state){try{state=await request('/api/heal?run_id='+encodeURIComponent(state.run_id));render(state);resume=!['COMPLETE','BLOCKED'].includes(state.phase);}catch{resume=false;sessionStorage.removeItem('nr-heal-run');}}
 }finally{busy=false;paused=false;document.body.classList.remove('paused');$('pause').textContent='Ⅱ';$('pause').setAttribute('aria-label','Pause recovery sequence');controls();}
};
$('pause').onclick=()=>{paused=!paused;document.body.classList.toggle('paused',paused);$('pause').textContent=paused?'▷':'Ⅱ';$('pause').setAttribute('aria-label',paused?'Resume recovery sequence':'Pause recovery sequence');};
$('replay').onclick=async()=>{if(busy||snapshots.length<2)return;busy=true;replaying=true;paused=false;controls();try{for(const s of snapshots){render(s);await waitBeat(s.phase==='WARNING'?2800:s.phase==='REPAIRING'?3200:1500);}}finally{replaying=false;busy=false;paused=false;document.body.classList.remove('paused');render(state);controls();}};
$('search').oninput=()=>{catalogPage=0;list();};$('filters').onclick=e=>{const b=e.target.closest('[data-filter]');if(!b||busy)return;filter=b.dataset.filter;catalogPage=0;list();};
$('evidence').onclick=()=>{
 if(!state)return;const rows=[['INCIDENT',`${selected.company} / ${selected.date} — ${selected.title}`],['SCOPE','Disposable service laboratory; persisted configuration and functional probes'],['OUTCOME',state.phase],['AI-SELECTED RUNBOOK',state.plan?.runbook||'No validated plan'],['INDEPENDENT CHECKS',state.verification?`${state.verification.checks_passed}/${state.verification.checks_total} · KMS signature verified`:'No normalization certificate'],['CONFIGURATION CHANGES',state.delta?state.delta.map(x=>x.field).join(', '):'No repair applied'],['REFERENCE',selected.adaptation]];
 if(isSecurity())rows.push(['DISCLOSED SCALE',`${selected.affected_count.toLocaleString('en-US')} ${selected.affected_label}`],['CONTAINMENT',state.verification?.containment?`${state.verification.containment.denied}/${state.verification.containment.attempted} unauthorized requests denied; legitimate read passed; evidence preserved`:'Not independently verified'],['HISTORICAL INCIDENT','Lab controls are defensive adaptations. Undisclosed vulnerabilities are not inferred. Previously leaked information is not recovered.']);
 const frag=document.createDocumentFragment();for(const [k,v] of rows){const p=document.createElement('p'),b=document.createElement('b');b.textContent=k+' / ';p.append(b,document.createTextNode(v));frag.append(p);}$('evidence-summary').replaceChildren(frag);$('dialog-source').href=selected.source;text('raw-evidence',JSON.stringify({incident:selected,result:state},null,2));$('evidence-dialog').showModal();
};
$('close-evidence').onclick=()=>$('evidence-dialog').close();
$('download').onclick=()=>{if(!state)return;const url=URL.createObjectURL(new Blob([JSON.stringify({incident:selected,result:state},null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download=`null-rebirth-${state.run_id}.json`;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);};
$('signout').onclick=async()=>{try{await request('/auth/logout',{});sessionStorage.removeItem('nr-heal-run');location.replace('/');}catch{ text('announcement','Sign out could not complete. Please retry.');}};
window.addEventListener('pageshow',e=>{if(e.persisted)location.reload();});
(async()=>{try{const config=await request('/api/config');incidents=config.incidents;if(!Array.isArray(incidents)||incidents.length!==25)throw Error('Incident archive unavailable.');reset();select(incidents.find(i=>i.mode==='containment')||incidents[0],true);resizeBridge();const id=sessionStorage.getItem('nr-heal-run');if(id&&/^run-[a-f0-9]{32}$/.test(id)){try{const saved=await request('/api/heal?run_id='+id);const incident=incidents.find(i=>i.id===saved.scenario);if(incident){select(incident,true);state=saved;snapshots=[saved];resume=!['COMPLETE','BLOCKED'].includes(saved.phase);render(saved);controls();}}catch{sessionStorage.removeItem('nr-heal-run');}}}catch(error){text('scene-status','BRIDGE UNAVAILABLE');text('scene-detail',error.message);document.body.dataset.stage='blocked';$('run').disabled=true;}})();
