const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, 'static/app.js'), 'utf8');
function functions(names) {
  return names.map(name => {
    const match = source.match(new RegExp(`^function ${name}\\([^\\n]*\\) \\{[\\s\\S]*?^\\}`, 'm'));
    assert.ok(match, name); return match[0];
  }).join('\n');
}
test('process search includes finding IDs, user, container and ports', () => {
  const fields = Object.fromEntries(['q','pid','user','name','path','risk','kernel'].map(k => ['f-'+k, {value:'',checked:false}]));
  const ctx = vm.createContext({$:id=>fields[id], tx:m=>m, riskNum:r=>['INFO','LOW','MEDIUM','HIGH','CRITICAL'].indexOf(r)});
  vm.runInContext(functions(['procFilter']),ctx);
  const p={pid:42,ppid:1,name:'worker',user:'service-user',exe:'/opt/app',cmdline:'worker',container:'web-container',risk:'LOW',ports:[43210],findings:[{id:'exe_packed',title:'Translated title'}]};
  for (const q of ['exe_packed','service-user','web-container','43210']) {fields['f-q'].value=q;assert.equal(ctx.procFilter()(p),true,q);}
  fields['f-q'].value='absent';assert.equal(ctx.procFilter()(p),false);
});
test('allowlist proposal and learning content stay text and copy only', () => {
  class Node {
    constructor(tag,text=''){this.tag=tag;this.text=text;this.children=[];this.events={};this.attrs={};}
    append(...children){this.children.push(...children);}
    replaceChildren(...children){this.children=children;}
    addEventListener(name,fn){this.events[name]=fn;}
    setAttribute(name,value){this.attrs[name]=value;}
    get textContent(){return this.text+this.children.map(c=>c.textContent).join('');}
  }
  const box=new Node('section');const payload='{"exe":"<img src=x onerror=attack()>"}';let copied;
  const ctx=vm.createContext({Node,document:{createElement:t=>new Node(t),createTextNode:t=>new Node('#text',t)},vis:String,tr:k=>k,tx:m=>m,fmtTime:String,copyText:s=>{copied=s},$:()=>box,state:{learning:{enabled:true,until:'tomorrow',baselineCommand:'serversecuritygo baseline save --name reviewed-fixture',warnings:['review'],candidates:[{exe:'<script>attack()</script>',user:'app',rule:'cpu_sustained',count:3,proposal:payload}]}},fetch:()=>{throw Error('unexpected mutation')}});
  vm.runInContext(functions(['h','allowlistProposal','renderLearning']),ctx);ctx.renderLearning();
  assert.ok(box.textContent.includes('<script>attack()</script>'));
  assert.ok(box.textContent.includes('baseline save --name reviewed-fixture'));
  const all=[];function walk(n){all.push(n);n.children.forEach(walk);}walk(box);
  assert.equal(all.some(n=>n.tag==='script'||n.tag==='img'),false);
  const button=all.find(n=>n.tag==='button');assert.ok(button);button.events.click();assert.equal(copied,payload);
  ctx.state.learning=null;ctx.renderLearning();assert.ok(box.textContent.includes('web.learning.disabled'));
});

test('overview preserves uncertainty, changes and all raw login fields', () => {
 class Node {
  constructor(tag,text=''){this.tag=tag;this.text=text;this.children=[];this.events={};this.dataset={};}
  append(...children){this.children.push(...children);}
  addEventListener(name,fn){this.events[name]=fn;}
  setAttribute(){}
  get textContent(){return this.text+this.children.map(c=>c.textContent).join('');}
 }
 const ctx=vm.createContext({Node,document:{createElement:t=>new Node(t),createTextNode:t=>new Node('#text',t)},vis:String,tr:(k,...args)=>k+' '+args.join(' '),fmtTime:String});
 vm.runInContext(functions(['h','kv','auditAttention','loginRows','loginGroupDetails']),ctx);
 for(const status of ['fail','warn','unknown','future']) assert.equal(ctx.auditAttention({status}),true);
 for(const status of ['pass','info','n/a']) {assert.equal(ctx.auditAttention({status}),false);assert.equal(ctx.auditAttention({status,change:true}),true);}
 const events=[{time:'2026-11-18T12:00:00Z',kind:'failed',ip:'192.0.2.1',source:'auth.log',user:'<script>bad()</script>',detail:'first',pid:42,tty:'pts/7',risk:'INFO'},
 {time:'2026-11-18T12:01:00Z',kind:'failed',ip:'192.0.2.1',source:'auth.log',user:'second',detail:'last',findings:['signal'],end:'session-end',fingerprint:'key',keyComment:'comment',risk:'HIGH'}];
 const groups=[{indices:[0,1],first:events[0].time,last:events[1].time,risk:'HIGH'}];
 const rows=ctx.loginRows(events,groups);
 assert.equal(rows[0].risk,'HIGH');assert.equal(rows[0].time,events[1].time);
 const fallback=ctx.loginRows(events,null);assert.equal(fallback.length,2);assert.equal(fallback[0].detail,'last');
 const node=ctx.loginGroupDetails(rows[0],events,new Set());
 assert.equal(node.textContent.includes('<script>'),false); // закрытые подробности ещё не построены
 node.open=true;node.events.toggle();
 for(const value of ['<script>bad()</script>','first','last','42','pts/7','signal','session-end','key comment']) assert.ok(node.textContent.includes(value),value);
 const content=node.textContent;node.events.toggle();assert.equal(node.textContent,content);
 const reopened=ctx.loginGroupDetails(rows[0],events,new Set([node.dataset.group]));assert.equal(reopened.open,true);assert.equal(reopened.textContent,content);
 function walk(n){assert.notEqual(n.tag,'script');n.children.forEach(walk);}walk(node);
});

test('audit default view retains unavailable checks; all results and search reveal routine checks', () => {
 const fields=Object.fromEntries(['btn-audit-run','audit-when','audit-score','a-q','a-status','a-group'].map(id=>[id,{value:''}]));
 const checks=[{id:'routine',status:'pass',title:'routine'}, {id:'unknown',status:'unknown'}, {id:'changed',status:'info',change:true}, {id:'warning',status:'warn'}];
 let rows;
 const ctx=vm.createContext({$:id=>fields[id],state:{audit:{enabled:false,checks}},tr:String,tx:m=>m||'',renderTable:(id,cols,data)=>{rows=data}});
 vm.runInContext(functions(['auditAttention','renderAudit']),ctx);
 fields['a-status'].value='attention';ctx.renderAudit();assert.deepEqual(Array.from(rows,c=>c.id),['unknown','changed','warning']);
 fields['a-q'].value='routine';ctx.renderAudit();assert.deepEqual(Array.from(rows,c=>c.id),['routine']);
 fields['a-q'].value='';fields['a-status'].value='';ctx.renderAudit();assert.equal(rows.length,4);
});

test('system details toggle and old API keep raw findings accessible', () => {
 const fields=Object.fromEntries(['sys-host','sys-warn','sys-overview','sys-all'].map(id=>[id,{checked:false,replaceChildren(){}}]));
 let rows;
 const findings=[{id:'routine'},{id:'unknown'},{id:'change'}];
 const ctx=vm.createContext({$:id=>fields[id],state:{system:{findings,overview:{attention:2,incomplete:1,details:[0]}}},tr:String,tx:String,kv:()=>[],yesNo:String,fmtTime:String,fmtAgo:String,fmtBytes:String,h:()=>({}),renderTable:(id,cols,data)=>{rows=data}});
 vm.runInContext(functions(['renderSystem']),ctx);ctx.renderSystem();assert.deepEqual(Array.from(rows,c=>c.id),['unknown','change']);
 fields['sys-all'].checked=true;ctx.renderSystem();assert.equal(rows.length,3);
 fields['sys-all'].checked=false;delete ctx.state.system.overview;ctx.renderSystem();assert.equal(rows.length,3);
});
