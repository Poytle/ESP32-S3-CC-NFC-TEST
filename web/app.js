/* Shared reducer is also exercised by host tests. No persistent browser storage. */
function cardKey(card) { return card.pan ? `pan:${card.pan}` : `uid:${card.uid || 'unknown'}`; }
function upsertCard(cards, card) {
 const key=cardKey(card), previous=cards.get(key);
 // Ignore a delayed event from an earlier scan of the same card.
 if(previous && Number(previous.scanId)>Number(card.scanId))return;
 cards.delete(key);cards.set(key,card);
 while(cards.size>32)cards.delete(cards.keys().next().value);
}
function debugExport(scans,device){
 return JSON.stringify({format:'nfc-lab.debug.v1',exportedAt:new Date().toISOString(),device,scans},null,2);
}
async function copyDebugText(text,clipboard,fallback){
 if(clipboard?.writeText){try{await clipboard.writeText(text);return 'clipboard';}catch(_){} }
 if(fallback && fallback(text))return 'fallback';
 return 'manual';
}
function receiveMessage(message,pending){
 if(message.type!=='chunk')return message;
 const {id,index,total,data}=message;
 if(!Number.isInteger(id)||!Number.isInteger(index)||!Number.isInteger(total)||total<1||total>128||index<0||index>=total||typeof data!=='string'||data.length>1400)throw Error('Invalid socket fragment');
 if(!pending.has(id)){while(pending.size>=2)pending.delete(pending.keys().next().value);pending.set(id,{total,parts:new Map()});}
 const entry=pending.get(id);if(entry.total!==total)throw Error('Inconsistent socket fragments');entry.parts.set(index,data);
 if(entry.parts.size!==total)return null;
 const bytes=[];for(let i=0;i<total;i++){const raw=atob(entry.parts.get(i));for(let j=0;j<raw.length;j++)bytes.push(raw.charCodeAt(j));}
 pending.delete(id);return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(new Uint8Array(bytes)));
}
if(typeof module!=='undefined')module.exports={cardKey,upsertCard,debugExport,copyDebugText,receiveMessage};
if(typeof document!=='undefined'){
 const $=id=>document.getElementById(id), cards=new Map();let socket,bootId,readerState={},pki={enrollments:{}};
 const node=(tag,text)=>{const e=document.createElement(tag);if(text!==undefined)e.textContent=text;return e;};
 function render(){
  const body=$('cards');body.replaceChildren();
  if(!cards.size){const row=node('tr'),cell=node('td','Waiting for a card…');cell.colSpan=7;cell.className='empty';row.append(cell);body.append(row);return;}
  for(const c of [...cards.values()].reverse()){
   const row=node('tr');for(const value of [c.pan||`UID ${c.uid}`,c.application||c.aid||'Unknown',c.taps||1,c.status,c.signingStatus])row.append(node('td',String(value||'—')));
   const verification=node('td',c.verification||'Awaiting proof');
   if(c.publicKey?.fingerprint)verification.append(node('pre',`Key fingerprint: ${c.publicKey.fingerprint}`));
   if(c.neededCapkRid)verification.append(node('pre',`CAPK needed: RID ${c.neededCapkRid}, index ${c.neededCapkIndex||'missing'}`));
   if(c.signatureVerified && !c.enrolled && !pki.enrollments?.[c.credentialId]){
    const enroll=node('button','Enroll public key');enroll.onclick=()=>pkiAction(enroll,'/api/pki/enroll',{id:c.credentialId,scanId:c.scanId});verification.append(enroll);
   }
   row.append(verification);
   const cell=node('td'),detail=node('details');detail.append(node('summary','Fields & signing'));
   const meta={uid:c.uid,aid:c.aid,aip:c.aip,scanId:c.scanId,seenMs:c.seenMs,verification:c.verification,signatureVerified:c.signatureVerified,retapVerified:c.retapVerified,chainTrusted:c.chainTrusted,certificateHashesVerified:c.certificateHashesVerified,credentialId:c.credentialId,publicKey:c.publicKey,trustPolicy:c.trustPolicy,proofMethod:c.proofMethod,signedDataFormat:c.signedDataFormat,signingMethod:c.signingMethod,fddaRequested:c.fddaRequested,terminalTtq:c.terminalTtq,terminalData:c.terminalData,signingChallenge:c.signingChallenge,ddolSource:c.ddolSource,signingResponse:c.signingResponse,requestedSignature:c.requestedSignature,dynamicSignatureSource:c.dynamicSignatureSource,dynamicSignature:c.dynamicSignature,readerError:c.readerError,failure:c.failure};
   const copy=node('button','Copy full scan data');copy.onclick=()=>copyScans([c]);detail.append(copy);
   detail.append(node('pre',JSON.stringify(meta,null,2)));
   if(c.fieldsTruncated)detail.append(node('p','Field display truncated at the device RAM limit (128 fields / 8 KB hex).'));
   const table=node('table'),head=node('tr');for(const name of ['Tag','Hex value','Printable text'])head.append(node('th',name));table.append(head);
   for(const f of c.fields||[]){const r=node('tr');r.append(node('td',f.tag),node('td',f.hex),node('td',f.text||''));table.append(r);}
   detail.append(table);const steps=node('details');steps.append(node('summary','APDU results'),node('pre',JSON.stringify(c.steps||[],null,2)));detail.append(steps);cell.append(detail);row.append(cell);body.append(row);
  }
 }
 async function copyScans(scans){
  if(!scans.length){$('copyStatus').textContent='No scans to copy yet.';return;}
  const text=debugExport(scans,{host:location.host,bootId,reader:readerState});
  const result=await copyDebugText(text,navigator.clipboard,contents=>{
   const textarea=node('textarea');textarea.value=contents;textarea.style.position='fixed';textarea.style.opacity='0';document.body.append(textarea);
   textarea.focus();textarea.select();textarea.setSelectionRange(0,contents.length);
   let copied=false;try{copied=Boolean(document.execCommand('copy'));}catch(_){}textarea.remove();return copied;
  });
  if(result==='manual'){$('manualCopy').hidden=false;$('copyText').value=text;$('copyText').focus();$('copyText').select();$('copyStatus').textContent='Automatic clipboard access was blocked. Copy the selected JSON below.';}
  else{$('manualCopy').hidden=true;$('copyStatus').textContent=`Copied ${scans.length} full scan${scans.length===1?'':'s'} to clipboard.`;}
 }
 $('copyAll').onclick=()=>copyScans([...cards.values()]);
 function setPki(config){
  pki=config;
  if(config.capk?.modulus)$('capk').value=JSON.stringify(config.capk,null,2);
  const target=$('enrollments');target.replaceChildren();
  for(const [id,entry] of Object.entries(config.enrollments||{})){
   const block=node('details');block.append(node('summary',`Enrolled key ${entry.publicKey.fingerprint.slice(0,16)}…`),node('pre',JSON.stringify(entry,null,2)));
   const forget=node('button','Forget enrollment');forget.onclick=()=>pkiAction(forget,'/api/pki/forget',{id});block.append(forget);target.append(block);
  }
 }
 async function pkiAction(button,path,payload){
  button.disabled=true;try{
   const response=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload||{})});
   const text=await response.text();if(!response.ok)throw Error(text);$('pkiMessage').textContent=text;
  }catch(e){$('pkiMessage').textContent=e.message;}finally{button.disabled=false;}
 }
 $('saveCapk').onclick=()=>{try{pkiAction($('saveCapk'),'/api/pki/capk',JSON.parse($('capk').value));}catch(e){$('pkiMessage').textContent=e.message;}};
 $('selftest').onclick=()=>pkiAction($('selftest'),'/api/pki/selftest');
 function connect(){
  const pending=new Map();
  socket=new WebSocket(`wss://${location.host}/ws`);
  socket.onopen=()=>{$('connection').textContent='Live';$('error').textContent='';};
  socket.onmessage=event=>{try{
   const message=receiveMessage(JSON.parse(event.data),pending);if(!message)return;
   if(message.type==='card'){upsertCard(cards,message.card);render();}
   else if(message.type==='pki'){setPki(message.card);render();}
   else if(message.type==='clear'){cards.clear();render();}
   else if(message.type==='reader'){readerState=message.card;if(bootId && bootId!==message.card.bootId){cards.clear();render();}bootId=message.card.bootId;$('reader').textContent=message.card.readerReady?`Reader ready — tap a card · Build ${message.card.firmwareBuild||'unknown'}`:`Reader unavailable: ${message.card.readerError}`;}
  }catch(e){$('error').textContent=`Invalid update: ${e.message}`;}};
  socket.onclose=()=>{$('connection').textContent='Reconnecting…';setTimeout(connect,1500);};
  socket.onerror=()=>socket.close();
 }
 async function action(id,path){$(id).disabled=true;try{const r=await fetch(path,{method:'POST'});if(!r.ok)throw Error(await r.text());return r;}catch(e){$('error').textContent=e.message;}finally{$(id).disabled=false;}}
 $('scan').onclick=()=>action('scan','/api/scan');$('clear').onclick=()=>action('clear','/api/clear');
 $('demo').onclick=async()=>{const r=await action('demo','/api/demo');if(r)$('proof').textContent=JSON.stringify(await r.json(),null,2);};
 connect();
}
