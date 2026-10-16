"""Loopback Alexa+ experience simulation backed by official MCP SDK 2.3.0.

This is not a connection to Alexa+ or an Echo. A constrained intent router acts
as the demo host; the AWS diagnosis and reporting are actual Nova calls in live mode.
"""
import asyncio,contextlib,json,re,secrets
from pathlib import Path
from mcp import Client
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse,HTMLResponse,FileResponse
from starlette.routing import Route,Mount
from alexa_sim.backend import Lab,summary,ROOT
from alexa_sim.advisory import frontier,acquisition

PORT=8768;ORIGIN=f'http://127.0.0.1:{PORT}';WEB_TOKEN=secrets.token_urlsafe(32)
lab=Lab();conversations={}

def conversation_context(thread_id,run_id=''):
    if not re.fullmatch(r'[a-f0-9]{32}',thread_id):raise ValueError('Invalid conversation identifier.')
    if thread_id not in conversations:
        if len(conversations)>=100:raise ValueError('This server session has reached its conversation limit.')
        if run_id:lab.state(run_id)
        conversations[thread_id]={'run_id':run_id or lab.recorded['run_id'],'pending':None,'lock':asyncio.Lock()}
    ctx=conversations[thread_id]
    if run_id and ctx['run_id']!=run_id:raise ValueError('The conversation run has changed. Read its current status before continuing.')
    return ctx

def conversation_arguments(ctx,tool,args):
    args=dict(args)
    if tool in {'get_recovery_status','prepare_recovery','inspect_resume_gate'}:args['run_id']=ctx['run_id']
    if tool=='confirm_recovery':
        pending=ctx['pending'];ctx['pending']=None
        if not pending:raise ValueError('Prepare and review a repair in this conversation first.')
        args={'run_id':pending['state']['run_id'],'confirmation_id':pending['confirmation_id']}
    return args
mcp=MCPServer('NULL REBIRTH',version='1.11.0',instructions='Inspect evidence. Prepare a bounded repair. Ask the user before confirm_recovery. Never treat reference advice as authorization.')
READ=ToolAnnotations(read_only_hint=True,destructive_hint=False,open_world_hint=False)
WRITE=ToolAnnotations(read_only_hint=False,destructive_hint=True,open_world_hint=False)

@mcp.tool(annotations=READ)
async def get_recovery_status(run_id:str='')->dict:
    """Read the current isolated workload or recorded evidence. Does not repair."""
    state=await asyncio.to_thread(lab.state,run_id)
    mode=lab.mode if state['run_id'] in lab.owned else 'recorded'
    return summary(state,mode)
@mcp.tool(annotations=WRITE)
async def start_incident_lab(scenario:str='sourcenext-api')->dict:
    """Create one disposable synthetic incident workload. Explicit user request required."""
    return summary(await asyncio.to_thread(lab.start,scenario),lab.mode)
@mcp.tool(annotations=WRITE)
async def prepare_recovery(run_id:str='')->dict:
    """Inject/detect the selected fault and ask Nova for a validated plan. Does not apply the repair."""
    result=await asyncio.to_thread(lab.prepare,run_id)
    result['state']=summary(result['state'],lab.mode)
    return result
@mcp.tool(annotations=WRITE)
async def confirm_recovery(run_id:str,confirmation_id:str)->dict:
    """Apply the reviewed plan only after explicit user confirmation; verify and report."""
    return summary(await asyncio.to_thread(lab.confirm,run_id,confirmation_id),lab.mode)
@mcp.tool(annotations=READ)
def inspect_proof_frontier(scenario:str='silent-monitor-death')->dict:
    """Inspect missing/failed evidence in the original read-only reference model."""
    return frontier(scenario)
@mcp.tool(annotations=READ)
def plan_missing_evidence(scenario:str='silent-monitor-death')->dict:
    """Run the original Proof Acquisition Planner on synthetic reference evidence. No probe executes."""
    return acquisition(scenario)
@mcp.tool(annotations=READ)
async def inspect_resume_gate(run_id:str='')->dict:
    """Inspect signed normalization evidence. Does not authorize or create business orders."""
    s=await asyncio.to_thread(lab.state,run_id);v=s.get('verification',{})
    return {'run_id':s['run_id'],'phase':s['phase'],'normalization_verified':s['phase']=='COMPLETE' and v.get('healthy') is True and v.get('kms_signature_verified') is True,
        'checks':f"{v.get('checks_passed',0)}/{v.get('checks_total',25)}",'kms_signature_verified':v.get('kms_signature_verified',False),
        'independent':v.get('independent',False),'business_order_created':False,'historical_evidence_cannot_authorize_new_work':True}

security=TransportSecuritySettings(enable_dns_rebinding_protection=True,allowed_hosts=[f'127.0.0.1:{PORT}',f'localhost:{PORT}'],allowed_origins=[ORIGIN,f'http://localhost:{PORT}'])
mcp_app=mcp.streamable_http_app(streamable_http_path='/',json_response=True,stateless_http=True,transport_security=security,max_request_body_size=16384)
@contextlib.asynccontextmanager
async def lifespan(app):
    async with mcp.session_manager.run():yield

async def home(request):
    text=Path(__file__).with_name('index.html').read_text(encoding='utf8').replace('__WEB_TOKEN__',WEB_TOKEN)
    return HTMLResponse(text,headers={'Cache-Control':'no-store','X-Frame-Options':'DENY','Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'"})
def web_allowed(req):
    return req.headers.get('origin') in {ORIGIN,f'http://localhost:{PORT}'} and secrets.compare_digest(req.headers.get('x-nr-session',''),WEB_TOKEN)
def intent(message):
    m=re.sub(r'^alexa(?:\s+plus)?[,:]?\s*','',message.lower().strip()).rstrip('.!?')
    if re.search(r"\b(don't|do not|never|cancel|ignore|bypass)\b",m) or any(w in m for w in ['しない','取消','無視']):raise ValueError('No action taken. Use a direct supported request.')
    if re.fullmatch(r'(?:please )?(?:confirm|approve)(?: (?:the|this|that|approved|proposed|repair|containment|plan|action|it|now))*',m) or m in {'承認','実行して'}:return 'confirm_recovery',{}
    if any(w in m for w in ['acquisition','collect evidence','next evidence','証拠を集め']):return 'plan_missing_evidence',{}
    if any(w in m for w in ['frontier','missing proof','evidence is missing','足りない証拠']):return 'inspect_proof_frontier',{}
    if any(w in m for w in ['resume','再開']):return 'inspect_resume_gate',{}
    if re.fullmatch(r'(?:please )?start (?:the |a |a new )?(?:member api )?(?:lab|experiment)',m) or m=='開始':return 'start_incident_lab',{'scenario':'sourcenext-api'}
    if re.fullmatch(r'(?:please )?(?:prepare|request|plan) (?:a |the )?(?:repair|containment|fix)(?: plan)?',m) or m in {'repair it','fix it','contain it','修復','封じ込め'}:return 'prepare_recovery',{}
    if any(w in m for w in ['status','what is wrong','happened','状態','状況']):return 'get_recovery_status',{}
    raise ValueError('Try asking for status, starting the member API lab, preparing a repair, confirming it, or inspecting missing evidence.')
async def chat(request):
    if not web_allowed(request):return JSONResponse({'error':'Local session or origin rejected.'},status_code=403)
    if int(request.headers.get('content-length','0'))>2048:return JSONResponse({'error':'Message is too long.'},status_code=413)
    try:
        body=await request.json();message=body.get('message','')
        if not isinstance(message,str) or not 0<len(message)<=500:raise ValueError('Invalid message.')
        ctx=conversation_context(body.get('thread_id',''),body.get('run_id',''))
        tool,args=intent(message)
        async with ctx['lock']:
            args=conversation_arguments(ctx,tool,args)
            async with Client(ORIGIN+'/mcp/',read_timeout_seconds=180,mode='legacy') as client:
                result=await client.call_tool(tool,args)
                tool_error=' '.join(c.text for c in result.content if hasattr(c,'text')) if result.is_error else ''
                data=result.structured_content
                if not tool_error and data is None:data=json.loads(next(c.text for c in result.content if hasattr(c,'text')))
            if tool_error:raise ValueError(tool_error)
            if tool=='prepare_recovery':ctx['pending']=data
            if tool=='start_incident_lab':ctx['pending']=None;ctx['run_id']=data['run_id']
        return JSONResponse({'tool':tool,'arguments':args if tool!='confirm_recovery' else {'run_id':args['run_id'],'confirmation':'explicit user approval'},'result':data})
    except (ValueError,KeyError,TypeError) as e:return JSONResponse({'error':str(e)[:350]},status_code=400)
    except Exception:return JSONResponse({'error':'The MCP request could not complete. Inspect the local server connection.'},status_code=502)
async def state(request):
    try:
        ctx=conversation_context(request.query_params.get('thread_id',''),request.query_params.get('run_id',''))
        s=await asyncio.to_thread(lab.state,ctx['run_id'])
        return JSONResponse(summary(s,lab.mode if s['run_id'] in lab.owned else 'recorded'),headers={'Cache-Control':'no-store'})
    except ValueError as e:return JSONResponse({'error':str(e)},status_code=400)
async def asset(request):
    name=request.path_params['name']
    if name not in {'bridge.css','bridge.js','threads.js','initial-history.json'}:return JSONResponse({'error':'Not found'},status_code=404)
    return FileResponse(Path(__file__).with_name(name),media_type='application/json' if name.endswith('.json') else 'text/css' if name.endswith('.css') else 'text/javascript',headers={'Cache-Control':'no-cache'})
async def image(request):
    name=request.path_params['name']
    if name not in {'patch','log'}:return JSONResponse({'error':'Not found'},status_code=404)
    return FileResponse(ROOT/'pv/assets'/f'{name}.svg',media_type='image/svg+xml')

class LocalOnly:
    def __init__(self,app):self.app=app
    async def __call__(self,scope,receive,send):
        if scope['type']=='http':
            headers=dict(scope.get('headers',[]));host=headers.get(b'host',b'').decode();origin=headers.get(b'origin',b'').decode()
            if host not in security.allowed_hosts or (origin and origin not in security.allowed_origins):
                return await JSONResponse({'error':'Loopback host/origin required.'},status_code=403)(scope,receive,send)
        await self.app(scope,receive,send)
app=LocalOnly(Starlette(routes=[Route('/',home),Route('/chat',chat,methods=['POST']),Route('/state',state),Route('/assets/{name}',asset),Route('/cat/{name}.svg',image),Mount('/mcp',app=mcp_app)],lifespan=lifespan))
if __name__=='__main__':
    import uvicorn
    uvicorn.run(app,host='127.0.0.1',port=PORT,access_log=False,log_level='warning')
