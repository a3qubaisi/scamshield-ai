// Run: node tests/engine.test.js
const path=require('path');
const E=require(path.join(__dirname,'../src/engine.js'));
let fail=0,n=0;
const check=(ok,msg)=>{n++;if(!ok){fail++;console.log('FAIL',msg);}};
// 1) labelled real-world-style messages written by hand (NOT from the training templates)
const CASES=require('./cases.json');
for(const c of CASES){const r=E.analyzeMessage(c.text);const scam=r.level==='high'||r.level==='crit';
  check(c.scam?scam:!scam,`${c.scam?'scam':'legit'} scored ${r.score}/${r.level} ml=${r.ml&&r.ml.p.toFixed(2)} :: ${c.text.slice(0,60)}`);}
// 2) URL forensics
const U=[['https://adpolice.gov.ae',false],['http://uaepass-login.com/verify',true],['https://emlratesnbd.com',true],['https://tamm-gov-ae.online/fines',true],['http://185.243.11.4/aramex/pay',true],['https://www.aramex.com/track',false],['https://xn--adpolce-9za.com',true]];
for(const [u,bad] of U){const a=E.analyzeUrl(u);check(bad?a.pts>=25:a.pts<=0,`url ${u} pts=${a.pts}`);}
// 3) JS model == Python model (parity with sklearn probabilities)
const ref=require('./parity.json');let maxd=0;
for(const r of ref){const d=Math.abs(E.mlScore(r.t).p-r.p);maxd=Math.max(maxd,d);}
check(maxd<1e-3,`JS/Python model parity max diff ${maxd}`);
console.log(`${n-fail}/${n} passed  (model parity max diff ${maxd.toExponential(2)})`);
process.exit(fail?1:0);
