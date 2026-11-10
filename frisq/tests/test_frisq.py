import importlib.util, pathlib, tempfile, unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('frisq',ROOT/'scripts/frisq.py');f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
class TestFrisq(unittest.TestCase):
 def test_scan_no_execute(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d);(p/'x.js').write_text('element.innerHTML = value;\n')
   r=f.scan(p);self.assertEqual(r['security_approval'],'NOT_VERIFIED');self.assertEqual(len(r['findings']),1)
 def test_symlink_not_followed(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d)
   try:(p/'x.js').symlink_to('/etc/passwd')
   except (OSError,NotImplementedError):self.skipTest('symlinks need privileges on this OS')
   self.assertEqual(f.scan(p)['files_inspected'],0)
 def test_empty_evidence_blocks(self):
  self.assertEqual(f.gate({'commit':'abc','environment':'test','controls':[]})['decision'],'BLOCK')
 def test_fake_pass_blocks(self):
  x=[{'control_id':c,'status':'PASS'} for c in f.MANDATORY]
  self.assertEqual(f.gate({'commit':'abc','environment':'test','controls':x})['decision'],'BLOCK')
 def test_verified_evidence_approves(self):
  x=[{'control_id':c,'status':'PASS','method':'test','tool_version':'1','timestamp_utc':'2026-11-10T00:00:00Z','evidence_ref':'artifact'} for c in f.MANDATORY]
  self.assertEqual(f.gate({'commit':'abc','environment':'test','controls':x})['decision'],'APPROVE')
 def test_high_fail_blocks(self):
  x=[{'control_id':c,'status':'PASS','method':'test','tool_version':'1','timestamp_utc':'2026-11-10T00:00:00Z','evidence_ref':'artifact'} for c in f.MANDATORY]
  x[0]['status']='FAIL';x[0]['severity']='HIGH'
  self.assertEqual(f.gate({'commit':'abc','environment':'test','controls':x})['decision'],'BLOCK')
 def test_na_needs_reason(self):
  x=[{'control_id':c,'status':'NOT_APPLICABLE'} for c in f.MANDATORY]
  self.assertEqual(f.gate({'commit':'abc','environment':'test','controls':x})['decision'],'BLOCK')
def ok(ids,**extra):
 return [dict({'control_id':c,'status':'PASS','method':'test','tool_version':'1','timestamp_utc':'2026-11-10T00:00:00Z','evidence_ref':'artifact'},**extra) for c in ids]
class TestGateV03(unittest.TestCase):
 def g(self,controls,**kw):return f.gate(dict({'commit':'abc','environment':'test','controls':controls},**kw))
 def test_profile_adds_mandatory(self):
  r=self.g(ok(f.BASE),profile='ctma');self.assertEqual(r['decision'],'BLOCK');self.assertIn('AI-01',r['mandatory_unverified'])
 def test_profile_satisfied_approves(self):
  self.assertEqual(self.g(ok(f.BASE+['AI-01','EDGE-01']),profile='ctma')['decision'],'APPROVE')
 def test_unknown_profile_rejected(self):
  with self.assertRaises(ValueError):self.g(ok(f.BASE),profile='nope')
 def test_other_commit_evidence_blocks(self):
  self.assertEqual(self.g(ok(f.BASE,commit='zzz'))['decision'],'BLOCK')
 def test_unknown_control_blocks(self):
  self.assertEqual(self.g(ok(f.BASE+['MADE-UP']))['decision'],'BLOCK')
 def test_expired_exception_blocks(self):
  x=ok(f.BASE);x[0].update(status='FAIL',severity='LOW',exception_id='E1',exception_expiry='2020-01-01T00:00:00Z')
  self.assertEqual(self.g(x)['decision'],'BLOCK')
 def test_low_fail_with_live_exception_is_review(self):
  x=ok(f.BASE);x[0].update(status='FAIL',severity='LOW',exception_id='E1',exception_expiry='2999-01-01T00:00:00Z')
  self.assertEqual(self.g(x)['decision'],'REVIEW')
 def test_na_required_needs_reviewer(self):
  x=ok(f.BASE);x[0]={'control_id':'ID-01','status':'NOT_APPLICABLE','reason':'no login'}
  self.assertEqual(self.g(x)['decision'],'BLOCK')
class TestScanV03(unittest.TestCase):
 def test_new_rules(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d);(p/'a.yml').write_text('on: pull_request_target\nuses: actions/checkout@v4\n');(p/'b.sql').write_text('alter table x disable row level security;\n')
   ids={(i['control_id'],i['severity']) for i in f.scan(p)['findings']};self.assertIn(('DEPLOY-01','HIGH'),ids);self.assertIn(('DATA-01','HIGH'),ids);self.assertIn(('SUPPLY-01','LOW'),ids)
 def test_secret_value_not_echoed(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d);(p/'c.js').write_text('const key="AKIAABCDEFGHIJKLMNOP";\n');r=f.scan(p);self.assertNotIn('AKIAABCDEFGHIJKLMNOP',str(r));self.assertEqual(r['findings'][0]['control_id'],'SECRETS-01')
if __name__=='__main__':unittest.main()
