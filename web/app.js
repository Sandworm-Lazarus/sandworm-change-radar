'use strict';
(function(){
  const $=id=>document.getElementById(id),project=document.body.dataset.project;
  let active=null,request=0;
  function status(s){$('status').textContent=s;}
  function reset(){request++;active=null;$('summary').replaceChildren();$('results').replaceChildren();$('details').textContent='';$('hash').textContent='—';$('mode').textContent='READY';$('export').disabled=true;$('filter').value='';$('count').textContent='ผลตรวจจะแสดงหลังนำเข้ารายงาน';$('review').checked=false;}
  function render(){
    const query=$('filter').value.trim().toLocaleLowerCase();$('results').replaceChildren();
    const rows=SandwormReport.entries(active),filtered=rows.filter(r=>JSON.stringify(r).toLocaleLowerCase().includes(query));
    for(const row of filtered.slice(0,300)){
      const item=document.createElement('details'),title=document.createElement('summary'),pre=document.createElement('pre');
      const value=row&&typeof row==='object'?row:{};
      title.textContent=String(value.title??value.rule_id??value.rule??value.package??value.name??value.id??value.claim??'Finding');
      pre.textContent=JSON.stringify(row,null,2);item.append(title,pre);$('results').append(item);
    }
    $('count').textContent=`${filtered.length} / ${rows.length} findings${filtered.length>300?' · แสดง 300 รายการแรก':''}`;
  }
  async function load(text){
    const id=++request;active=null;$('export').disabled=true;$('review').checked=false;
    try{
      const report=SandwormReport.parse(text,project);SandwormReport.entries(report);
      const digest=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(text));if(id!==request)return;
      active=report;$('hash').textContent=Array.from(new Uint8Array(digest),b=>b.toString(16).padStart(2,'0')).join('');
      $('mode').textContent=report.mode.toUpperCase();$('summary').replaceChildren();
      for(const [key,value]of Object.entries(report.summary).slice(0,12)){
        if(value&&typeof value==='object')continue;
        const card=document.createElement('div'),strong=document.createElement('strong'),label=document.createElement('span');
        strong.textContent=String(value??'unknown');label.textContent=key;card.append(strong,label);$('summary').append(card);
      }
      $('details').textContent=JSON.stringify(report,null,2);render();status('อ่านรายงานแล้ว · ตรวจทานข้อมูลก่อนแชร์');
    }catch{if(id===request){reset();status('อ่านรายงานไม่ได้ · ตรวจ project, schema, mode, key ซ้ำ และขนาดไฟล์');}}
  }
  $('sample').addEventListener('click',async()=>{
    const id=++request;
    try{const response=await fetch('./demo.json',{cache:'no-store'});if(!response.ok)throw Error();const text=await response.text();if(id===request)await load(text);}catch{if(id===request)status('โหลดตัวอย่างไม่ได้ · เปิดผ่าน HTTP และตรวจไฟล์ demo.json');}
  });
  $('file').addEventListener('change',async event=>{
    const file=event.target.files[0];if(!file)return;
    const id=++request;
    if(file.size>SandwormReport.MAX_BYTES){reset();status('ไฟล์ใหญ่เกิน 2 MiB');return;}
    try{const text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(await file.arrayBuffer());if(id===request)await load(text);}catch{if(id===request){reset();status('ไฟล์ต้องเป็น UTF-8 JSON');}}
    event.target.value='';
  });
  $('clear').addEventListener('click',()=>{reset();status('ล้างรายงานแล้ว');});
  $('filter').addEventListener('input',()=>{if(active)render();});
  $('review').addEventListener('change',()=>{$('export').disabled=!active||!$('review').checked;});
  $('export').addEventListener('click',()=>{if(!active||!$('review').checked)return;const blob=new Blob([JSON.stringify(active,null,2)+'\n'],{type:'application/json'}),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download=project+'-reviewed-report.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});
})();
