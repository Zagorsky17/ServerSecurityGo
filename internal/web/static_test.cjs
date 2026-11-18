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
  const nodes=Object.fromEntries(['sys-host','sys-warn','sys-group-nav'].map(id=>[id,new Node('div')]));let table;
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
  vm.runInContext(functions(['renderAudit']),ctx);
  ctx.renderAudit();assert.ok(!fields['audit-when'].textContent.includes('inventory_'));
  a.inventorySource={ready:false,incomplete:true};ctx.renderAudit();assert.ok(fields['audit-when'].textContent.includes('inventory_pending'));
  a.inventorySource={ready:true,incomplete:true,time:'2026-11-18T00:30:00Z'};ctx.renderAudit();
  assert.ok(fields['audit-when'].textContent.includes(a.time));assert.ok(fields['audit-when'].textContent.includes(a.inventorySource.time));assert.ok(fields['audit-when'].textContent.includes('inventory_incomplete'));
  a.inventorySource.incomplete=false;ctx.renderAudit();assert.ok(fields['audit-when'].textContent.includes('inventory_complete'));
  a.enabled=false;ctx.renderAudit();assert.ok(!fields['audit-when'].textContent.includes('inventory_'));
});
