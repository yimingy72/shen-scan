package main

import (
	"encoding/json"
	"fmt"

	"scanplatform/webprobe/browserfp"
)

// Each plan is data, never executable expressions. Access is bracket traversal
// and own-property checks, matching the historical JS and DOM drivers.
func browserCollector(plan browserfp.Plan) (string, error) {
	raw, err := json.Marshal(plan)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`() => {
 const plan=%s, output={js:{},dom:{}};
 const own=Object.prototype.hasOwnProperty, limit=1024;
 let bytes=0,nodes=0;
 const error=e=>String(e&&e.message||e).slice(0,256);
 function value(v,present=true) {
  if(!present)return {exists:false,type:'undefined'};
  const type=v===null?'null':typeof v;
  const result={exists:true,type};
  if(type==='object'||type==='function'||type==='symbol')return result;
  const text=String(v);
  if(text.length>limit||bytes+text.length>524288){result.truncated=true;result.error='value budget exceeded';result.value=text.slice(0,Math.min(limit,Math.max(0,524288-bytes)));}
  else result.value=text;
  bytes+=result.value.length;
  return result;
 }
 function property(object,key,dom=false) {
  if(object===null||(typeof object!=='object'&&typeof object!=='function')||!own.call(object,key))return value(undefined,false);
  const v=object[key];
  return value(v,!(dom&&v===undefined));
 }
 for(const path of plan.js) {
  try {
   let current=window,found=true;
   for(const part of path.parts) {
    if(current===null||(typeof current!=='object'&&typeof current!=='function')||!own.call(current,part)){found=false;break;}
    current=current[part];
   }
   output.js[path.key]=value(current,found);
  }catch(e){output.js[path.key]={exists:false,type:'undefined',error:error(e)};}
 }
 for(const selector of plan.dom) {
  const observation={nodes:[]};output.dom[selector.selector]=observation;
  try {
   const found=document.querySelectorAll(selector.selector);
   const count=Math.min(found.length,32,Math.max(0,1024-nodes));
   if(count<found.length) {observation.truncated=true;observation.error='DOM node budget exceeded';}
   for(let i=0;i<count;i++) {
    nodes++;const node=found[i],ob={text:{exists:false,type:'undefined'},attributes:{},properties:{}};
    if(selector.text)try{const text=node.innerText.trim();ob.text=value(text,text.length>0);}catch(e){ob.text={exists:false,type:'undefined',error:error(e)};}
    for(const key of selector.attributes||[])try{ob.attributes[key]=value(node.getAttribute(key),node.hasAttribute(key));}catch(e){ob.attributes[key]={exists:false,type:'undefined',error:error(e)};}
    for(const key of selector.properties||[])try{ob.properties[key]=property(node,key,true);}catch(e){ob.properties[key]={exists:false,type:'undefined',error:error(e)};}
    observation.nodes.push(ob);
   }
  }catch(e){observation.error=error(e);}
 }
 return output;
}`, string(raw)), nil
}
