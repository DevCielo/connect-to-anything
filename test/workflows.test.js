import test from "node:test";
import assert from "node:assert/strict";
import { compileHar, executeWorkflow, validateWorkflow } from "../src/workflows.js";

const har = {
  log:{ entries:[{
    request:{ method:"POST", url:"https://legacy.example/api/records?token=should-disappear&view=full", headers:[{name:"Authorization",value:"Bearer secret"},{name:"X-Client-Version",value:"1"}], postData:{ mimeType:"application/json", text:JSON.stringify({name:"Example",password:"secret",nested:{api_key:"secret"}}) } },
    response:{ status:201 },
  }] },
};

test("HAR compiler produces a single-origin redacted review artifact", () => {
  const workflow=compileHar(har,{name:"Create record"});
  assert.equal(workflow.origin,"https://legacy.example"); assert.equal(workflow.steps.length,1);
  const request=workflow.steps[0].request;
  assert.equal(request.headers.authorization,undefined); assert.equal(request.headers["x-client-version"],"1");
  assert.equal(request.path.includes("should-disappear"),false); assert.equal(request.path.includes("%5BREDACTED%5D"),true);
  assert.equal(request.body.password,"[REDACTED]"); assert.equal(request.body.nested.api_key,"[REDACTED]");
});

test("workflow executor templates inputs, extracts outputs and stops on drift", async () => {
  const definition=validateWorkflow({ schema_version:1,name:"Read record",origin:"https://legacy.example",inputs:{record_id:"string"},steps:[
    {id:"lookup",request:{method:"GET",path:"api/records/{{inputs.record_id}}"},assert:{status:[200]},extract:{name:"data.name"}},
    {id:"confirm",request:{method:"POST",path:"api/confirm",body:{name:"{{steps.lookup.extracted.name}}"}},assert:{status:[204]},extract:{}},
  ]});
  const requests=[]; const responses=[new Response(JSON.stringify({data:{name:"Road job",token:"never log"}}),{status:200,headers:{"content-type":"application/json"}}),new Response(null,{status:204})];
  const result=await executeWorkflow({definition,inputs:{record_id:"123"},request:async request=>{requests.push(request);return responses.shift();}});
  assert.equal(requests[0].path,"api/records/123"); assert.deepEqual(requests[1].body,{name:"Road job"}); assert.equal(result.steps[0].body.data.token,"[REDACTED]"); assert.equal(JSON.stringify(result.outputs).includes("never log"),false);

  const driftDefinition={...definition,steps:[{...definition.steps[0],assert:{status:[201]}}]};
  await assert.rejects(()=>executeWorkflow({definition:driftDefinition,inputs:{record_id:"123"},request:async()=>new Response("no",{status:500})}),error=>error.drift===true && error.results[0].status===500);
});

test("HAR compiler rejects multi-origin and oversized captures", () => {
  const multi=structuredClone(har); multi.log.entries.push({...multi.log.entries[0],request:{...multi.log.entries[0].request,url:"https://other.example/api"}});
  assert.throws(()=>compileHar(multi,{name:"unsafe"}),/one origin/i);
  const oversized={log:{entries:Array.from({length:51},()=>har.log.entries[0])}};
  assert.throws(()=>compileHar(oversized,{name:"too large"}),/more than 50/i);
});
