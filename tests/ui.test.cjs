const test=require('node:test');const assert=require('node:assert/strict');
const {cardKey,upsertCard}=require('../web/app.js');
test('scan and subsequent signing update replace one PAN row, even with a different UID',()=>{
 const cards=new Map();upsertCard(cards,{pan:'1234567890123456',uid:'AA',scanId:1,taps:1,signingStatus:'Pending'});
 upsertCard(cards,{pan:'1234567890123456',uid:'BB',scanId:1,taps:1,signingStatus:'Signature returned'});
 assert.equal(cards.size,1);assert.equal([...cards.values()][0].signingStatus,'Signature returned');
 upsertCard(cards,{pan:'1234567890123456',scanId:2,taps:2});assert.equal(cards.size,1);assert.equal([...cards.values()][0].taps,2);
 upsertCard(cards,{pan:'1234567890123456',scanId:1,taps:1});assert.equal([...cards.values()][0].scanId,2);
});
test('different full PANs sharing last four digits stay separate',()=>{
 const cards=new Map();for(const pan of ['1111111111111234','2222222222221234'])upsertCard(cards,{pan,scanId:1});assert.equal(cards.size,2);
});
test('nonpayment tags use UID fallback and list memory is bounded',()=>{
 assert.equal(cardKey({uid:'ABCD'}),'uid:ABCD');const cards=new Map();
 for(let i=0;i<40;i++)upsertCard(cards,{uid:String(i),scanId:i});assert.equal(cards.size,32);assert(!cards.has('uid:0'));
 cards.clear();assert.equal(cards.size,0);
});
const {debugExport,copyDebugText}=require('../web/app.js');
test('debug export preserves full scan, unknown fields, errors, signatures and public key',()=>{
 const scan={pan:'4111111111111111',fields:[{tag:'9F46',hex:'ABCD'}],steps:[{command:'READ RECORD',detail:'example failure'}],publicKey:{modulus:'1234',exponent:'03'},requestedSignature:'CDEF',signatureVerified:false,unknownFutureField:{present:true}};
 const output=JSON.parse(debugExport([scan],{bootId:'test',host:'192.168.4.1:433'}));
 assert.deepEqual(output.scans,[scan]);assert.equal(output.device.bootId,'test');assert.equal(output.format,'nfc-lab.debug.v1');
});
test('clipboard uses native API and does not invoke fallback after success',async()=>{
 let value;assert.equal(await copyDebugText('full JSON',{writeText:async text=>{value=text;}},()=>{throw Error('unexpected fallback');}),'clipboard');assert.equal(value,'full JSON');
});
test('clipboard denial and missing secure clipboard API support fallback/manual copy',async()=>{
 assert.equal(await copyDebugText('data',{writeText:async()=>{throw Error('NotAllowedError');}},text=>text==='data'),'fallback');
 assert.equal(await copyDebugText('data',undefined,()=>false),'manual');
});
const {receiveMessage}=require('../web/app.js');
test('large secure socket updates reassemble full UTF-8 JSON across frame boundaries',()=>{
 const original={type:'card',card:{fields:[{text:'é—☃'.repeat(500)}],signatureVerified:true}};
 const bytes=Buffer.from(JSON.stringify(original)),pending=new Map();let result;
 const total=Math.ceil(bytes.length/1024);
 for(let index=0;index<total;index++)result=receiveMessage({type:'chunk',id:1,index,total,data:bytes.subarray(index*1024,(index+1)*1024).toString('base64')},pending);
 assert.deepEqual(result,original);assert.equal(pending.size,0);
 assert.throws(()=>receiveMessage({type:'chunk',id:2,index:0,total:1000000,data:''},pending));
});
