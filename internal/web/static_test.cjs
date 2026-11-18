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
