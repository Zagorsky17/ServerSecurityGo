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
