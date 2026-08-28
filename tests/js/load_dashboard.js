/* dash/*.js 18개를 dashboard.html 순서대로 실제 로드해 보는 하네스.
 *
 * 브라우저가 없으므로 document·Chart·io·$ 등은 "무엇을 물어도 자기 자신을
 * 돌려주는" Proxy 로 흉내낸다. 이것으로 검증할 수 있는 것은 두 가지다:
 *   1) 18개가 로드 시점에 예외 없이 평가되는가 (전역 이름 충돌은 여기서 죽는다)
 *   2) 로드가 끝난 뒤, 인라인 핸들러·다른 파일이 필요로 하는 이름이 window 에 있는가
 *
 * 2번이 핵심이다. 각 파일을 IIFE 로 감싼 뒤에는 Object.assign(window, {...}) 로
 * 명시 공개한 이름만 밖에서 보인다 — 하나라도 빠뜨리면 클릭이 조용히 죽는데,
 * 그 조용함을 여기서 시끄럽게 만든다.
 *
 * 사용: node tests/js/load_dashboard.js <dash디렉터리> <필요한이름.json>
 */
const fs=require('fs'),path=require('path'),vm=require('vm');
const dir=process.argv[2], required=JSON.parse(fs.readFileSync(process.argv[3],'utf8'));
function mock(n){const f=function(){return f};return new Proxy(f,{get(t,p){if(p===Symbol.toPrimitive)return()=>0;if(p==='then')return undefined;if(p==='length')return 0;if(p==='name')return n;if(p===Symbol.iterator)return function*(){};if(p in t)return t[p];return mock(n+'.'+String(p))},set(){return true},apply(){return mock(n+'()')},construct(){return mock('new '+n)},has(){return true}})}
const s={};s.globalThis=s;s.window=s;s.console=console;s.setTimeout=()=>0;s.clearTimeout=()=>{};s.setInterval=()=>0;s.clearInterval=()=>{};s.requestAnimationFrame=()=>0;
s.fetch=()=>({then:()=>({then:()=>({catch:()=>{}}),catch:()=>{}}),catch:()=>{}});
for(const g of ['document','navigator','location','localStorage','Chart','io','DataTable','bootstrap','Globe','THREE','CSS','URLSearchParams','Image','Blob','FormData','AbortController','WebSocket','alert','confirm','prompt','getComputedStyle','MutationObserver','IntersectionObserver','ResizeObserver','screen','history','performance'])s[g]=mock(g);
s.$=mock('$');s.jQuery=s.$;
const stubs=new Set(Object.keys(s));
vm.createContext(s);
const files=fs.readdirSync(dir).filter(f=>/^\d\d-.*\.js$/.test(f)).sort();
const failures=[];
for(const f of files){try{vm.runInContext(fs.readFileSync(path.join(dir,f),'utf8'),s,{filename:f})}catch(e){failures.push({file:f,error:e.name+': '+e.message})}}
const missing=required.filter(n=>!(n in s)&&!stubs.has(n));
console.log(JSON.stringify({loadFailures:failures,requiredCount:required.length,missingAfterLoad:missing},null,2));
