'use strict';
(function(root,factory){const api=factory();if(typeof module==='object'&&module.exports)module.exports=api;else root.SandwormReport=api;})(typeof globalThis==='object'?globalThis:this,function(){
  const MAX_BYTES=2*1024*1024;
  function parse(text,project){
    if(typeof text!=='string'||new TextEncoder().encode(text).length>MAX_BYTES)throw Error('รายงานต้องเป็น UTF-8 JSON ขนาดไม่เกิน 2 MiB');
    let i=0,nodes=0;
    const fail=()=>{throw Error('รูปแบบ JSON ไม่ถูกต้อง หรือมี key ซ้ำ');};
    function space(){while(/[\t\n\r ]/.test(text[i]||'!'))i++;}
    function string(){const start=i++;while(i<text.length){if(text[i]==='\\'){i+=2;continue;}if(text[i++]==='"'){try{return JSON.parse(text.slice(start,i));}catch{fail();}}}fail();}
    function value(depth){
      if(depth>40||++nodes>30000)throw Error('รายงานมีโครงสร้างซับซ้อนเกินขอบเขต');
      space();const c=text[i];
      if(c==='"')return string();
      if(c==='{'){i++;space();const obj=Object.create(null),seen=new Set();if(text[i]==='}'){i++;return obj;}while(i<text.length){space();if(text[i]!=='"')fail();const k=string();if(seen.has(k))fail();seen.add(k);space();if(text[i++]!==':')fail();obj[k]=value(depth+1);space();const end=text[i++];if(end==='}')return obj;if(end!==',')fail();}fail();}
      if(c==='['){i++;space();const arr=[];if(text[i]===']'){i++;return arr;}while(i<text.length){arr.push(value(depth+1));space();const end=text[i++];if(end===']')return arr;if(end!==',')fail();}fail();}
      for(const [word,result] of [['true',true],['false',false],['null',null]])if(text.slice(i,i+word.length)===word){i+=word.length;return result;}
      const m=/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(text.slice(i));if(!m)fail();i+=m[0].length;const num=Number(m[0]);if(!Number.isFinite(num)||(Number.isInteger(num)&&!Number.isSafeInteger(num)))throw Error('ตัวเลขในรายงานเกินขอบเขตที่อ่านได้อย่างแม่นยำ');return num;
    }
    const result=value(0);space();if(i!==text.length)fail();
    if(!result||typeof result!=='object'||Array.isArray(result))throw Error('รายงานต้องเป็น JSON object');
    if(result.project!==project)throw Error('รายงานนี้เป็นของโปรเจกต์อื่น');
    if(result.schema_version!==1)throw Error('ยังไม่รองรับ schema version นี้');
    if(!['live','fixture','import'].includes(result.mode))throw Error('รายงานต้องระบุโหมด live, fixture หรือ import');
    if(!result.summary||typeof result.summary!=='object'||Array.isArray(result.summary))throw Error('ไม่พบ summary ของรายงาน');
    return result;
  }
  function entries(report){
    const rows=Array.isArray(report.findings)?report.findings:[];
    if(rows.length>10000)throw Error('รายการผลตรวจเกิน 10,000 รายการ');
    return rows;
  }
  return Object.freeze({parse,entries,MAX_BYTES});
});
