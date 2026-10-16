const KEY='null-rebirth.conversations.v1';
export class Threads {
  constructor(storage){this.storage=storage;this.items=[];this.activeId='';this.failed=false;this.hadSavedData=false;try{const v=JSON.parse(storage.getItem(KEY)||'null');if(v?.version===1&&Array.isArray(v.items)){this.hadSavedData=true;this.items=v.items.filter(t=>/^[a-f0-9]{32}$/.test(t.id)&&Array.isArray(t.messages)).slice(0,100);this.activeId=v.activeId;}}catch{this.failed=true;}if(!this.items.length)this.create();if(!this.items.some(t=>t.id===this.activeId))this.activeId=this.items[0].id;}
  active(){return this.items.find(t=>t.id===this.activeId);}
  save(){try{this.storage.setItem(KEY,JSON.stringify({version:1,activeId:this.activeId,items:this.items}));this.failed=false;}catch{this.failed=true;}return !this.failed;}
  create(){if(this.items.length>=100)throw Error('Conversation limit reached. Delete an unused conversation first.');const t={id:crypto.randomUUID().replaceAll('-',''),title:'New conversation',createdAt:Date.now(),updatedAt:Date.now(),messages:[],trace:[],run:null,frontier:'Inspect missing evidence. Read-only reference model.',planner:'Choose the next evidence probes. No probe executes.',awaiting:false};this.items.unshift(t);this.activeId=t.id;this.save();return t;}
  select(id){if(!this.items.some(t=>t.id===id))throw Error('Conversation not found.');this.activeId=id;this.save();return this.active();}
  add(thread,role,text,error=false){if(!this.items.includes(thread))return;thread.messages.push({role,text,error,time:Date.now()});thread.updatedAt=Date.now();if(role==='YOU'&&thread.title==='New conversation')thread.title=text.replace(/^alexa(?: plus)?[, :]*/i,'').slice(0,75);this.save();}
  remove(ids){const set=new Set(ids);this.items=this.items.filter(t=>!set.has(t.id));if(!this.items.length)this.create();else if(set.has(this.activeId))this.activeId=this.items[0].id;this.save();return this.active();}
}
