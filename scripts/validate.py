import hashlib,json,pathlib,subprocess,sys,unittest
root=pathlib.Path(__file__).resolve().parents[1]
suite=unittest.defaultTestLoader.discover(str(root/'tests'))
result=unittest.TextTestRunner(verbosity=1).run(suite)
if not result.wasSuccessful():raise SystemExit(1)
web=subprocess.run(['node','--test','--test-reporter=tap','tests/web.test.cjs'],cwd=root,capture_output=True,text=True)
if web.returncode:print(web.stdout,web.stderr);raise SystemExit(1)
import re
web_count=int(re.search(r'# tests (\d+)',web.stdout).group(1))
manifest={}
for name in ['src','tests','examples','scripts','web']:
 for path in sorted((root/name).rglob('*')):
  if path.is_file() and '__pycache__' not in path.parts:
   manifest[str(path.relative_to(root))]=hashlib.sha256(path.read_bytes()).hexdigest()
validation={'schema_version':1,'project':'sandworm-change-radar','passed':result.testsRun+web_count,'failed':0,'source_sha256':manifest,
 'upstream_check':{'name':'changedetection.io','contract_version':'0.70.3','status':'contract_mock_passed','scope':'local HTTP API contract fixture tests; actual upstream server smoke recorded separately when available'}}
proof=root/'reports/upstream-live.json'
if proof.exists():
 validation['recorded_upstream_evidence']={'path':'reports/upstream-live.json','sha256':hashlib.sha256(proof.read_bytes()).hexdigest(),'note':'Recorded optional real-upstream API-resource run; not rerun by this dependency-free validator'}
(root/'reports/validation.json').write_text(json.dumps(validation,indent=2)+'\n')
print(f'PASS {result.testsRun+web_count} tests; validation hashes refreshed')
