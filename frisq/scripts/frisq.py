#!/usr/bin/env python3
"""FRISQ offline, non-executing source indicators and conservative evidence gate."""
import argparse, datetime, json, pathlib, re, subprocess, sys
VERSION='0.3.0'
SKIP={'.git','node_modules','.next','dist','build','.venv','venv','coverage','.turbo','.cache'}
EXTS={'.js','.jsx','.ts','.tsx','.py','.go','.java','.rb','.php','.yml','.yaml','.json','.toml','.env','.sh','.tf','.sql','.html','.vue','.svelte'}
RULES=[
 ('WEB-01','MEDIUM','Review direct HTML insertion',r'\bdangerouslySetInnerHTML\b|\binnerHTML\s*='),
 ('WEB-01','HIGH','Possible permissive CORS header',r'Access-Control-Allow-Origin["\x27\s:]+\*'),
 ('SUPPLY-01','MEDIUM','Review dynamic code execution',r'\beval\s*\(|\bshell\s*=\s*True\b'),
 ('SECRETS-01','CRITICAL','Possible private key material',r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
 ('CLOUD-01','HIGH','Possible public S3 ACL',r'public-read-write|"ACL"\s*:\s*"public-read"'),
 ('DEPLOY-01','MEDIUM','Possible privileged CI token',r'permissions:\s*write-all'),
 ('DEPLOY-01','HIGH','pull_request_target trigger: review untrusted checkout risk',r'\bpull_request_target\b'),
 ('SECRETS-01','CRITICAL','Possible AWS access key id',r'\bAKIA[0-9A-Z]{16}\b'),
 ('SECRETS-01','HIGH','Possible hard-coded token/secret assignment',r'(?:api[_-]?key|secret|token|passwd|password)["\x27]?\s*[:=]\s*["\x27][A-Za-z0-9_\-/+=]{20,}["\x27]'),
 ('SECRETS-01','HIGH','Service-role key referenced in code: confirm server-only',r'service_role|SUPABASE_SERVICE_ROLE'),
 ('DATA-01','MEDIUM','Table created or altered: confirm RLS is enabled',r'create\s+table\b'),
 ('DATA-01','HIGH','RLS explicitly disabled',r'disable\s+row\s+level\s+security'),
 ('WEB-01','MEDIUM','Review open-redirect style sink',r'(?:res\.redirect|window\.location(?:\.href)?\s*=|redirect\()\s*\(?\s*(?:req\.|params|searchParams|query)'),
 ('SUPPLY-01','LOW','Unpinned GitHub Action (tag, not commit SHA)',r'uses:\s*[\w.-]+/[\w./-]+@(?![0-9a-f]{40}\b)\S+'),
]
PATTERNS=[(a,b,c,re.compile(d,re.I)) for a,b,c,d in RULES]
MAX_BYTES=512000
BASE=['ID-01','AUTHZ-01','TENANT-01','DATA-01','SECRETS-01','WEB-01','API-01','FILE-01','SUPPLY-01','LOG-01','BACKUP-01','DEPLOY-01','PRIV-01','OPS-01']
MANDATORY=BASE  # kept for backwards compatibility with v0.2 callers/tests
CATALOG=set(BASE)|{'EDGE-01','CLOUD-01','CHAT-01','AI-01','UX-01','PAY-01'}
# Extra mandatory controls per product, on top of BASE. Defaults for the owner to review; see references/PRODUCT_PROFILES.md.
PROFILES={'pattio':['EDGE-01','CLOUD-01','UX-01'],'vault':['EDGE-01','CHAT-01','UX-01'],'replio':['EDGE-01','CHAT-01'],'lytics':['EDGE-01','UX-01'],'ctma':['AI-01','EDGE-01'],'client-site':['UX-01']}
STATUSES={'PASS','FAIL','NOT_VERIFIED','NOT_APPLICABLE'}
SEVERITIES={'CRITICAL','HIGH','MEDIUM','LOW','INFO'}
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def commit(root):
 try:return subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],stderr=subprocess.DEVNULL,text=True,timeout=4).strip()
 except (OSError,subprocess.SubprocessError):return None
def scan(root):
 findings=[];count=0;skipped=0
 for p in sorted(root.rglob('*')):
  if p.is_symlink() or not p.is_file() or any(part in SKIP for part in p.relative_to(root).parts):continue
  if p.suffix not in EXTS and p.name not in {'.env','Dockerfile','.github'}:continue
  try:
   if p.stat().st_size>MAX_BYTES:skipped+=1;continue
   lines=p.read_text(encoding='utf-8').splitlines()
  except (OSError,UnicodeError):skipped+=1;continue
  count+=1
  for number,line in enumerate(lines,1):
   for cid,severity,message,pattern in PATTERNS:
    if pattern.search(line):findings.append({'control_id':cid,'severity':severity,'message':message,'file':str(p.relative_to(root)),'line':number,'status':'REVIEW_REQUIRED'})
 return {'schema_version':1,'tool':'FRISQ static indicators','version':VERSION,'timestamp_utc':now(),'target':str(root),'commit':commit(root),'files_inspected':count,'files_skipped':skipped,'findings':findings,'security_approval':'NOT_VERIFIED','limitations':'Heuristic indicators only; no proof of exploit or security; no commands executed from target.'}
def parse_time(v):
 try:
  t=datetime.datetime.fromisoformat(str(v).replace('Z','+00:00'))
  return t if t.tzinfo else t.replace(tzinfo=datetime.timezone.utc)
 except ValueError:return None
def gate(data,profile=None):
 if not isinstance(data,dict) or not isinstance(data.get('controls'),list):raise ValueError('controls array required')
 if not data.get('commit') or not data.get('environment'):raise ValueError('commit and environment required')
 profile=profile or data.get('profile')
 if profile is not None and profile not in PROFILES:raise ValueError('unknown profile: '+str(profile)+' (known: '+', '.join(sorted(PROFILES))+')')
 required=BASE+[c for c in PROFILES.get(profile,[]) if c not in BASE]
 now_utc=datetime.datetime.now(datetime.timezone.utc)
 records={};errors=[]
 for c in data['controls']:
  if not isinstance(c,dict):errors.append('Invalid control record');continue
  cid=c.get('control_id');status=c.get('status')
  if not isinstance(cid,str) or status not in STATUSES:errors.append('Invalid control ID/status');continue
  if cid not in CATALOG:errors.append('Unknown control: '+cid);continue
  if cid in records:errors.append('Duplicate control: '+cid);continue
  if 'severity' in c and str(c['severity']).upper() not in SEVERITIES:errors.append('Invalid severity: '+cid);continue
  if status=='PASS':
   if not c.get('evidence_ref') or not c.get('method') or not c.get('timestamp_utc') or not c.get('tool_version'):errors.append('PASS missing evidence: '+cid)
   elif parse_time(c['timestamp_utc']) is None:errors.append('PASS has unreadable timestamp: '+cid)
   if c.get('commit') and c['commit']!=data['commit']:errors.append('PASS evidence is for a different commit: '+cid)
  if status=='NOT_APPLICABLE':
   if not c.get('reason'):errors.append('N/A missing reason: '+cid)
   if cid in required and not c.get('reviewer'):errors.append('N/A on required control needs a named reviewer: '+cid)
  if status=='FAIL' and c.get('exception_id'):
   exp=parse_time(c.get('exception_expiry'))
   if exp is None or exp<=now_utc:errors.append('Exception missing or expired: '+cid)
  records[cid]=c
 missing=[cid for cid in required if cid not in records or records[cid]['status']=='NOT_VERIFIED']
 blocking=[cid for cid,c in records.items() if c['status']=='FAIL' and str(c.get('severity','HIGH')).upper() in ('CRITICAL','HIGH')]
 # A live exception is recorded but never turns a FAIL into APPROVE: medium/low failures stay at REVIEW.
 decision='BLOCK' if errors or missing or blocking else 'REVIEW' if any(c['status']=='FAIL' for c in records.values()) or any(c['status']=='NOT_APPLICABLE' for c in records.values()) else 'APPROVE'
 return {'tool':'FRISQ evidence gate','version':VERSION,'timestamp_utc':now(),'commit':data['commit'],'environment':data['environment'],'profile':profile,'required_controls':required,'decision':decision,'blocking_failures':blocking,'mandatory_unverified':missing,'validation_errors':errors,'limitations':'Only evaluates supplied evidence; does not independently authenticate evidence or guarantee safety.'}
def write(path,record):
 target=pathlib.Path(path);target.parent.mkdir(parents=True,exist_ok=True);target.write_text(json.dumps(record,indent=2)+'\n',encoding='utf8')
def main():
 parser=argparse.ArgumentParser(description='FRISQ evidence-first security assistant');sub=parser.add_subparsers(dest='command',required=True)
 s=sub.add_parser('scan');s.add_argument('path');s.add_argument('--output',default='frisq-report.json')
 g=sub.add_parser('gate');g.add_argument('evidence');g.add_argument('--profile',choices=sorted(PROFILES),help='product profile adding mandatory controls');g.add_argument('--output',default='frisq-decision.json')
 a=parser.parse_args()
 if a.command=='scan':
  root=pathlib.Path(a.path).resolve()
  if not root.is_dir():parser.error('Target must be a directory')
  result=scan(root);write(a.output,result)
  print(f"FRISQ scan: {len(result['findings'])} indicators; {result['files_inspected']} files; security NOT_VERIFIED")
 else:
  try:result=gate(json.loads(pathlib.Path(a.evidence).read_text(encoding='utf8')),a.profile)
  except (OSError,ValueError,json.JSONDecodeError) as e:parser.error(str(e))
  write(a.output,result);print('FRISQ gate:',result['decision'])
  if result['decision']=='BLOCK':sys.exit(2)
if __name__=='__main__':main()
