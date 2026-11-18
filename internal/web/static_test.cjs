const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, 'static/app.js'), 'utf8');
function functions(names) {
  return names.map(name => {
    const match = source.match(new RegExp(`^(?:async )?function ${name}\\([^\\n]*\\) \\{[\\s\\S]*?^\\}`, 'm'));
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

test('system groups preserve every finding and fall back for older services', () => {
  const ctx=vm.createContext({tr:(key,n)=>key+': '+n});
  vm.runInContext(functions(['systemRows']),ctx);
  const findings=Array.from({length:7229},(_,i)=>({id:'fs_unowned',path:'/opt/app/tree/'+i,risk:'MEDIUM'}));
  findings.push({id:'other',path:'/etc/critical',risk:'CRITICAL'});
  const group={key:'stable',directory:'/opt/app/tree',owner:'uid=501 gid=50',indices:Array.from({length:7229},(_,i)=>i)};
  const s={findings,groups:[group]};const before=JSON.stringify(s);
  const rows=ctx.systemRows(s,'');assert.equal(rows.length,2);assert.equal(rows[1],findings[7229]);
  const members=ctx.systemRows(s,'stable');assert.equal(members.length,7229);members.forEach((f,i)=>assert.equal(f,findings[i]));
  assert.equal(ctx.systemRows(s,'removed').length,2);
  assert.equal(ctx.systemRows({findings},'stable').length,7230);
  assert.equal(JSON.stringify(s),before);
});

test('system group buttons open members, survive refresh and return safely', () => {
  class Node {
    constructor(tag,text=''){this.tag=tag;this.text=text;this.children=[];this.events={};}
    append(...children){this.children.push(...children);}
    replaceChildren(...children){this.children=children;}
    addEventListener(name,fn){this.events[name]=fn;}
    setAttribute(){}
    get textContent(){return this.text+this.children.map(c=>c.textContent).join('');}
  }
  const nodes=Object.fromEntries(['sys-host','sys-warn','sys-group-nav','sys-overview','sys-all'].map(id=>[id,new Node('div')]));let table;
  const members=[{title:'<img src=x onerror=attack()>',path:'/opt/app/a',risk:'MEDIUM'},{title:'second',path:'/opt/app/b',risk:'MEDIUM'}];
  const group={key:'group',directory:'/opt/app',owner:'uid=501 gid=50',indices:[0,1]};
  const state={system:{findings:members,groups:[group]},status:{},showAll:{}};
  const ctx=vm.createContext({Node,document:{createElement:t=>new Node(t),createTextNode:t=>new Node('#text',t)},vis:String,tx:m=>m,tr:(k,n)=>k+(n===undefined?'':n),$:id=>nodes[id],state,kv:()=>[],fmtTime:String,fmtAgo:String,fmtBytes:String,yesNo:String,riskNum:()=>1,riskBadge:String,findingContext:()=>'',renderTable:(id,cols,rows)=>{table={cols,rows}}});
  vm.runInContext(functions(['h','systemRows','systemFindingTitle','renderSystem']),ctx);
  ctx.renderSystem();assert.equal(table.rows.length,1);
  const button=ctx.systemFindingTitle(table.rows[0]);assert.equal(button.tag,'button');button.events.click();
  assert.equal(state.systemGroup,'group');assert.equal(table.rows.length,2);
  const title=table.cols[1].r(table.rows[0]);const cell=ctx.h('td',null,title);
  assert.ok(cell.textContent.includes('<img'));assert.equal(cell.children[0].tag,'#text');
  state.system={findings:[...members],groups:[{...group}]};ctx.renderSystem();assert.equal(table.rows.length,2);
  nodes['sys-group-nav'].children[0].events.click();assert.equal(state.systemGroup,'');assert.equal(table.rows.length,1);
  state.systemGroup='group';state.system.groups=[];ctx.renderSystem();assert.equal(state.systemGroup,'');assert.equal(table.rows.length,2);
  let requested;ctx.openSystemDetail=(index,revision)=>{requested=[index,revision]};
  members.forEach((f,i)=>f.index=i);members[1].reviewFirst=true;
  state.system={findings:members,groups:[group],summary:true,revision:'revision',overview:{attention:1,incomplete:0,details:[0]}};
  nodes['sys-all'].checked=false;ctx.renderSystem();assert.equal(table.rows.length,1);
  assert.equal(table.cols[4].r(table.rows[0]),'');
  ctx.systemFindingTitle(table.rows[0]).events.click();assert.equal(table.rows.length,1);assert.equal(table.rows[0].index,1);
  assert.ok(table.cols[1].r(table.rows[0]).textContent.includes('card.review_first'));
  table.cols[4].r(table.rows[0]).events.click();assert.deepEqual(requested,[1,'revision']);
  nodes['sys-all'].checked=true;ctx.renderSystem();assert.equal(table.rows.length,2);

});

test('finding cards separate evidence, confidence and safe verification text', () => {
  class Node {
    constructor(tag,text=''){this.tag=tag;this.text=text;this.children=[];this.attrs={};}
    append(...children){this.children.push(...children);}
    addEventListener(){}
    setAttribute(k,v){this.attrs[k]=v;}
    get textContent(){return this.text+this.children.map(c=>c.textContent).join('');}
  }
  const ctx=vm.createContext({Node,document:{createElement:t=>new Node(t),createTextNode:t=>new Node('#text',t)},vis:String,tr:k=>k,tx:m=>m || '',fmtTime:String,categoryName:String,allowlistProposal:()=>''});
  vm.runInContext(functions(['h','findingContext','findingBlock']),ctx);
  const f={title:'change',category:'network',reviewFirst:true,evidence:['OBSERVED <img src=x>'],why:'RISK',confidence:'LIMITS',legitimate:'maintenance',verifyCommands:['stat -- \'/tmp/<script>\''],attack:['javascript:evil','T1098.004']};
  const card=ctx.findingBlock(f);const text=card.textContent;
  let last=-1;for(const s of ['tui.h.facts','OBSERVED','card.why','RISK','card.confidence','LIMITS','card.verify','stat --']){const i=text.indexOf(s);assert.ok(i>last,s);last=i;}
  const nodes=[];function walk(n){nodes.push(n);n.children.forEach(walk);}walk(card);
  assert.equal(nodes.some(n=>n.tag==='img'||n.tag==='script'),false);
  assert.ok(nodes.find(n=>n.tag==='details').attrs.hasOwnProperty('open'));
  assert.equal(nodes.filter(n=>n.tag==='a').length,1);
  const suppressed=ctx.findingContext({...f,suppressed:true});assert.equal(Object.hasOwn(suppressed.attrs,'open'),false);
  const legacy=ctx.findingContext({why:'old',verifyCommands:[]});assert.ok(legacy.textContent.includes('old'));
});

test('audit distinguishes full check time from pending and incomplete inventory', () => {
  const fields=Object.fromEntries(['btn-audit-run','audit-when','audit-score','a-q','a-status','a-group'].map(k=>[k,{value:'',textContent:''}]));
  const a={enabled:true,ready:true,running:false,time:'2026-11-18T00:00:00Z',interval:3600,durationMs:10,summary:{fail:0,warn:0,info:0,na:0,unknown:4},checks:[]};
  const ctx=vm.createContext({$:id=>fields[id],state:{audit:a},tr:(k,...args)=>[k,...args].join(' '),fmtTime:String,tx:String,renderTable:()=>{}});
  vm.runInContext(functions(['auditAttention','renderAudit']),ctx);
  ctx.renderAudit();assert.ok(!fields['audit-when'].textContent.includes('inventory_'));
  a.inventorySource={ready:false,incomplete:true};ctx.renderAudit();assert.ok(fields['audit-when'].textContent.includes('inventory_pending'));
  a.inventorySource={ready:true,incomplete:true,time:'2026-11-18T00:30:00Z'};ctx.renderAudit();
  assert.ok(fields['audit-when'].textContent.includes(a.time));assert.ok(fields['audit-when'].textContent.includes(a.inventorySource.time));assert.ok(fields['audit-when'].textContent.includes('inventory_incomplete'));
  a.inventorySource.incomplete=false;ctx.renderAudit();assert.ok(fields['audit-when'].textContent.includes('inventory_complete'));
  a.enabled=false;ctx.renderAudit();assert.ok(!fields['audit-when'].textContent.includes('inventory_'));
});

test('conditional API keeps parsed reports in memory and invalidates on failure or mutation', async () => {
  const reportCache=new Map(),cachedPaths=new Set(['/api/system?summary=1']);let calls=0,decodes=0;
  const ctx=vm.createContext({reportCache,cachedPaths,I18N:{lang:'en'},state:{csrf:'fixture'},location:{},tr:k=>k,fetch:async(path,opts)=>{
    calls++;let status=200,data={findings:[{id:'fixture'}]},etag='"fixture"';
    if(calls===2){assert.equal(opts.headers['If-None-Match'],etag);status=304;}
    if(calls===3){status=503;data={error:'unavailable'};}
    if(calls===4){assert.equal(opts.headers['If-None-Match'],undefined);etag=null;}
    if(calls===5){assert.equal(opts.headers['If-None-Match'],undefined);}
    if(calls===6){assert.equal(opts.headers['X-CSRF-Token'],'fixture');assert.equal(reportCache.size,0);}
    if(calls===7)status=401;
    return {status,ok:status===200,headers:{get:()=>etag},json:async()=>{decodes++;if(status===304)throw Error('304 parsed');return data;}};
  }});
  vm.runInContext(functions(['api']),ctx);
  const first=await ctx.api('/api/system?summary=1');assert.equal(await ctx.api('/api/system?summary=1'),first);assert.equal(decodes,1);
  await assert.rejects(ctx.api('/api/system?summary=1'),/unavailable/);assert.equal(reportCache.size,0);
  await ctx.api('/api/system?summary=1');assert.equal(reportCache.size,0);
  await ctx.api('/api/system?summary=1');assert.equal(reportCache.size,1);
  await ctx.api('/api/rescan',{method:'POST'});assert.equal(reportCache.size,0);
  await assert.rejects(ctx.api('/api/system?summary=1'),/unauthorized/);assert.equal(ctx.location.href,'/login');assert.equal(reportCache.size,0);
});

test('unchanged reports skip table rendering while status still renders', () => {
  let headers=0,tables=0;
  const ctx=vm.createContext({state:{tab:'system',system:{}},I18N:{lang:'en'},renderSummary:()=>headers++,renderSystem:()=>tables++});
  vm.runInContext('let renderedReport=null;'+functions(['renderAll']),ctx);
  ctx.renderAll(true);ctx.state.status={stale:true};ctx.renderAll(true);
  assert.equal(headers,2);assert.equal(tables,1);
  ctx.renderAll();assert.equal(tables,2);
  ctx.I18N.lang='ru';ctx.renderAll(true);assert.equal(tables,3);
  ctx.state.system={};ctx.renderAll(true);assert.equal(tables,4);
});

test('system details load only on request with the matching revision', async () => {
  let requested='',rendered=null,visible=false,message='';
  const ctx=vm.createContext({api:async path=>{requested=path;return {evidence:['full facts']}},renderCard:data=>{rendered=data},$:()=>({classList:{remove:()=>visible=true}}),tr:(k,e)=>e,toast:s=>message=s});
  vm.runInContext('let cardData=null;'+functions(['openSystemDetail']),ctx);
  assert.equal(requested,'');await ctx.openSystemDetail(12,'"fixture"');
  assert.equal(requested,'/api/system/detail?index=12&revision=%22fixture%22');assert.equal(rendered.systemFinding.evidence[0],'full facts');assert.ok(visible);
  rendered=null;ctx.api=async()=>{throw Error('report changed')};await ctx.openSystemDetail(12,'"old"');assert.equal(rendered,null);assert.equal(message,'report changed');
});

test('refresh errors remain visible instead of marking cached data fresh', async () => {
  let shown=0;
  const ctx=vm.createContext({state:{refreshError:''},api:async()=>{throw Error('offline')},tr:(k,s)=>k+' '+s,renderSummary:()=>shown++,toast:()=>{}});
  vm.runInContext('let loading=false;'+functions(['refresh']),ctx);
  await ctx.refresh();assert.ok(ctx.state.refreshError.includes('offline'));assert.equal(shown,1);
});

test('overview preserves uncertainty, changes and all raw login fields', () => {
 class Node {
  constructor(tag,text=''){this.tag=tag;this.text=text;this.children=[];this.events={};this.dataset={};}
  append(...children){this.children.push(...children);}
  replaceChildren(...children){this.children=children;}
  addEventListener(name,fn){this.events[name]=fn;}
  setAttribute(){}
  get textContent(){return this.text+this.children.map(c=>c.textContent).join('');}
 }
 const ctx=vm.createContext({PAGE:400,Node,document:{createElement:t=>new Node(t),createTextNode:t=>new Node('#text',t)},vis:String,tr:(k,...args)=>k+' '+args.join(' '),fmtTime:String});
 vm.runInContext(functions(['h','kv','auditAttention','loginRows','loginGroupDetails']),ctx);
 for(const status of ['fail','warn','unknown','future']) assert.equal(ctx.auditAttention({status}),true);
 for(const status of ['pass','info','n/a']) {assert.equal(ctx.auditAttention({status}),false);assert.equal(ctx.auditAttention({status,change:true}),true);}
 const events=[{time:'2026-11-18T12:00:00Z',kind:'failed',ip:'192.0.2.1',source:'auth.log',user:'<script>bad()</script>',detail:'first',pid:42,tty:'pts/7',risk:'INFO'},
 {time:'2026-11-18T12:01:00Z',kind:'failed',ip:'192.0.2.1',source:'auth.log',user:'second',detail:'last',findings:['signal'],end:'session-end',fingerprint:'key',keyComment:'comment',risk:'HIGH'}];
 const groups=[{indices:[0,1],first:events[0].time,last:events[1].time,risk:'HIGH'}];
 const rows=ctx.loginRows(events,groups);
 assert.equal(rows[0].risk,'HIGH');assert.equal(rows[0].time,events[1].time);
 const fallback=ctx.loginRows(events,null);assert.equal(fallback.length,2);assert.equal(fallback[0].detail,'last');
 const node=ctx.loginGroupDetails(rows[0],events,new Map());
 assert.equal(node.textContent.includes('<script>'),false); // закрытые подробности ещё не построены
 node.open=true;node.events.toggle();
 for(const value of ['<script>bad()</script>','first','last','42','pts/7','signal','session-end','key comment']) assert.ok(node.textContent.includes(value),value);
 const content=node.textContent;node.events.toggle();assert.equal(node.textContent,content);
 const reopened=ctx.loginGroupDetails(rows[0],events,new Map([[node.dataset.group,false]]));assert.equal(reopened.open,true);assert.equal(reopened.textContent,content);
 function walk(n){assert.notEqual(n.tag,'script');n.children.forEach(walk);}walk(node);
 ctx.PAGE=1;
 const limited=ctx.loginGroupDetails(rows[0],events,new Map());limited.open=true;limited.events.toggle();
 assert.equal(limited.textContent.includes('last'),false);
 const button=limited.children[1].children.at(-1).children.find(n=>n.tag==='button');assert.ok(button);button.events.click();
 assert.ok(limited.textContent.includes('last'));assert.equal(limited.dataset.all,'true');
 const refreshed=ctx.loginGroupDetails(rows[0],events,new Map([[limited.dataset.group,true]]));assert.ok(refreshed.textContent.includes('last'));

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
 const fields=Object.fromEntries(['sys-host','sys-warn','sys-group-nav','sys-overview','sys-all'].map(id=>[id,{checked:false,replaceChildren(){}}]));
 let rows;
 const findings=[{id:'routine'},{id:'unknown'},{id:'change'}];
 const ctx=vm.createContext({$:id=>fields[id],state:{system:{findings,overview:{attention:2,incomplete:1,details:[0]}}},tr:String,tx:String,kv:()=>[],yesNo:String,fmtTime:String,fmtAgo:String,fmtBytes:String,h:()=>({}),renderTable:(id,cols,data)=>{rows=data}});
 vm.runInContext(functions(['systemRows','systemFindingTitle','renderSystem']),ctx);ctx.renderSystem();assert.deepEqual(Array.from(rows,c=>c.id),['unknown','change']);
 fields['sys-all'].checked=true;ctx.renderSystem();assert.equal(rows.length,3);
 fields['sys-all'].checked=false;delete ctx.state.system.overview;ctx.renderSystem();assert.equal(rows.length,3);
});
