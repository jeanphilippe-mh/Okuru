const assert=require("node:assert/strict"),fs=require("node:fs"),vm=require("node:vm");
class Element {
 constructor(){this.children=[];this.listeners={};this.textContent="";this.dataset={maxSize:"10"};this.value="1";this.files=[];}
 addEventListener(type,handler){this.listeners[type]=handler;}
 dispatchEvent(event){this.listeners[event.type]?.(event);}
 append(...nodes){this.children.push(...nodes);}
 replaceChildren(){this.children=[];}
 setAttribute(){}
 click(){this.listeners.click?.();}
}
const elements=Object.fromEntries(["files","file_create","selected-files","file-errors","ttl","ttl-value","ttlViews","ttlViews-value"].map(k=>[k,new Element()]));
const document={getElementById:id=>elements[id],createElement:()=>new Element(),querySelector:()=>elements["selected-files"].children[0].children[1],querySelectorAll:selector=>selector==="button"?elements["selected-files"].children.map(x=>x.children[1]):[]};
const w={document,File:class{constructor(parts,name,options={}){this.name=name;this.size=parts.join("").length;this.lastModified=options.lastModified||0;}},Event:class{constructor(type){this.type=type;this.defaultPrevented=false;}preventDefault(){this.defaultPrevented=true;}}};
class DataTransfer{constructor(){this.files=[];this.items={add:file=>this.files.push(file)};}}
const input=elements.files;let files=[];Object.defineProperty(input,"files",{get:()=>files,set:value=>files=value});
vm.runInNewContext(fs.readFileSync("public/scripts/file-upload.js","utf8"),{document,DataTransfer,Number,Set,Array});
function pick(...items){files=items;input.dispatchEvent(new w.Event("change"));}
const a=new w.File(["aaa"],"a.txt",{lastModified:1}),b=new w.File(["bb"],"b.txt",{lastModified:2});
pick(a);pick(b);assert.equal(files.length,2);pick(a);assert.equal(files.length,2);pick();assert.equal(files.length,2);
w.document.querySelector("button").click();assert.equal(files.length,1);assert.equal(files[0].name,"b.txt");
pick(new w.File(["123456789"],"large.txt"));const event=new w.Event("submit",{cancelable:true});w.document.getElementById("file_create").dispatchEvent(event);assert(event.defaultPrevented);
w.document.querySelectorAll("button")[1].click();assert.equal(w.document.getElementById("file-errors").textContent,"");
pick(new w.File(["x"],"<img src=x onerror=alert(1)>"));assert.equal(w.document.querySelectorAll("img").length,0);
console.log("Sequential selections, deduplication, cancellation, removal, aggregate limit and safe filenames passed.");
