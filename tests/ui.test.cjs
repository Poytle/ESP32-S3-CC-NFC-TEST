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
