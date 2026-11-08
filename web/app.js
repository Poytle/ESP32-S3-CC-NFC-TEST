/* Shared reducer is also exercised by host tests. No persistent browser storage. */
function cardKey(card) { return card.pan ? `pan:${card.pan}` : `uid:${card.uid || 'unknown'}`; }
function upsertCard(cards, card) {
 const key=cardKey(card), previous=cards.get(key);
 // Ignore a delayed event from an earlier scan of the same card.
 if(previous && Number(previous.scanId)>Number(card.scanId))return;
 cards.delete(key);cards.set(key,card);
 while(cards.size>32)cards.delete(cards.keys().next().value);
}
if(typeof module!=='undefined')module.exports={cardKey,upsertCard};
if(typeof document!=='undefined'){
 const $=id=>document.getElementById(id), cards=new Map();let socket,bootId;
 const node=(tag,text)=>{const e=document.createElement(tag);if(text!==undefined)e.textContent=text;return e;};
 function render(){
  const body=$('cards');body.replaceChildren();
  if(!cards.size){const row=node('tr'),cell=node('td','Waiting for a card…');cell.colSpan=6;cell.className='empty';row.append(cell);body.append(row);return;}
  for(const c of [...cards.values()].reverse()){
   const row=node('tr');for(const value of [c.pan||`UID ${c.uid}`,c.application||c.aid||'Unknown',c.taps||1,c.status,c.signingStatus])row.append(node('td',String(value||'—')));
   const cell=node('td'),detail=node('details');detail.append(node('summary','Fields & signing'));
   const meta={uid:c.uid,aid:c.aid,aip:c.aip,scanId:c.scanId,seenMs:c.seenMs,verification:c.verification,signingMethod:c.signingMethod,fddaRequested:c.fddaRequested,terminalTtq:c.terminalTtq,terminalData:c.terminalData,signingChallenge:c.signingChallenge,ddolSource:c.ddolSource,signingResponse:c.signingResponse,requestedSignature:c.requestedSignature,dynamicSignatureSource:c.dynamicSignatureSource,dynamicSignature:c.dynamicSignature,readerError:c.readerError,failure:c.failure};
   detail.append(node('pre',JSON.stringify(meta,null,2)));
   if(c.fieldsTruncated)detail.append(node('p','Field display truncated at the device RAM limit (128 fields / 8 KB hex).'));
   const table=node('table'),head=node('tr');for(const name of ['Tag','Hex value','Printable text'])head.append(node('th',name));table.append(head);
   for(const f of c.fields||[]){const r=node('tr');r.append(node('td',f.tag),node('td',f.hex),node('td',f.text||''));table.append(r);}
   detail.append(table);const steps=node('details');steps.append(node('summary','APDU results'),node('pre',JSON.stringify(c.steps||[],null,2)));detail.append(steps);cell.append(detail);row.append(cell);body.append(row);
  }
 }
 function connect(){
  socket=new WebSocket(`ws://${location.hostname}:81/`);
  socket.onopen=()=>{$('connection').textContent='Live';$('error').textContent='';};
  socket.onmessage=event=>{try{
   const message=JSON.parse(event.data);
   if(message.type==='card'){upsertCard(cards,message.card);render();}
   else if(message.type==='clear'){cards.clear();render();}
   else if(message.type==='reader'){if(bootId && bootId!==message.card.bootId){cards.clear();render();}bootId=message.card.bootId;$('reader').textContent=message.card.readerReady?'Reader ready — tap a card':`Reader unavailable: ${message.card.readerError}`;}
  }catch(e){$('error').textContent=`Invalid update: ${e.message}`;}};
  socket.onclose=()=>{$('connection').textContent='Reconnecting…';setTimeout(connect,1500);};
  socket.onerror=()=>socket.close();
 }
 async function action(id,path){$(id).disabled=true;try{const r=await fetch(path,{method:'POST'});if(!r.ok)throw Error(await r.text());return r;}catch(e){$('error').textContent=e.message;}finally{$(id).disabled=false;}}
 $('scan').onclick=()=>action('scan','/api/scan');$('clear').onclick=()=>action('clear','/api/clear');
 $('demo').onclick=async()=>{const r=await action('demo','/api/demo');if(r)$('proof').textContent=JSON.stringify(await r.json(),null,2);};
 connect();
}
