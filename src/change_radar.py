"""Read-only changedetection.io API client; original Sandworm comparison logic."""
from __future__ import annotations
import argparse, difflib, hashlib, http.client, ipaddress, json, os, re, socket, ssl, sys, unicodedata
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

VERSION = '0.1.0'
UPSTREAM_VERSION = '0.70.3'
MAX_BYTES = 262144
MAX_LINES = 4000
WATCH = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')

class RadarError(Exception):
    """A fixed, non-sensitive error code suitable for logs."""

def sha(data: str | bytes) -> str:
    return hashlib.sha256(data.encode('utf-8') if isinstance(data, str) else data).hexdigest()

def load_json(text: str):
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise RadarError('DUPLICATE_JSON_KEY')
            out[key] = value
        return out
    if len(text.encode('utf-8')) > MAX_BYTES:
        raise RadarError('INPUT_LIMIT')
    try:
        return json.loads(text, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(RadarError('INVALID_JSON')))
    except (ValueError, RecursionError):
        raise RadarError('INVALID_JSON') from None

def read_text(path: str) -> str:
    try:
        with open(path, 'rb') as f:
            raw = f.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise RadarError('INPUT_LIMIT')
        return raw.decode('utf-8')
    except (OSError, UnicodeError):
        raise RadarError('INPUT_READ_FAILED') from None

def normalize(text: str, ignore_prefixes=()) -> list[str]:
    if not isinstance(text, str) or len(text.encode('utf-8')) > MAX_BYTES:
        raise RadarError('SNAPSHOT_LIMIT')
    if not isinstance(ignore_prefixes, (tuple,list)) or len(ignore_prefixes) > 16 or any(not isinstance(v, str) or not v or len(v)>128 or '\n' in v or '\r' in v for v in ignore_prefixes):
        raise RadarError('INVALID_IGNORE_PREFIXES')
    lines = unicodedata.normalize('NFC', text).replace('\r\n','\n').replace('\r','\n').splitlines()
    if len(lines) > MAX_LINES:
        raise RadarError('LINE_LIMIT')
    return [line.rstrip() for line in lines if not any(line.startswith(p) for p in ignore_prefixes)]

def compare(before: str, after: str, ignore_prefixes=(), *, include_diff=False, mode='import', upstream_diff=None):
    if mode not in ('fixture','import','live'):
        raise RadarError('INVALID_MODE')
    a, b = normalize(before,ignore_prefixes), normalize(after,ignore_prefixes)
    changes = []
    for tag, i, j, k, l in difflib.SequenceMatcher(None,a,b,autojunk=False).get_opcodes():
        if tag != 'equal':
            item={'id':f'change-{len(changes)+1}','status':tag,'before_lines':[i+1,j],'after_lines':[k+1,l],
                  'before_sha256':sha('\n'.join(a[i:j])),'after_sha256':sha('\n'.join(b[k:l])),
                  'message':'เนื้อหาส่วนนี้เปลี่ยน ตรวจเทียบ snapshot ต้นทาง'}
            if include_diff:
                item.update(before=a[i:j],after=b[k:l])
            changes.append(item)
    report={'schema_version':1,'project':'sandworm-change-radar','engine_version':VERSION,'mode':mode,
            'upstream':{'name':'changedetection.io','contract_version':UPSTREAM_VERSION},
            'summary':{'changed':a!=b,'change_blocks':len(changes),'before_lines':len(a),'after_lines':len(b)},
            'findings':changes,'evidence':{'before_sha256':sha(before),'after_sha256':sha(after),
               'normalized_before_sha256':sha('\n'.join(a)),'normalized_after_sha256':sha('\n'.join(b)),
               'ignore_prefixes_sha256':sha(json.dumps(list(ignore_prefixes),ensure_ascii=False))},
            'privacy':{'raw_snapshot_included':bool(include_diff),'origin_and_watch_id_omitted':True},
            'boundaries':['Diff does not establish truth or detect every semantic change.','Ignore rules can hide meaningful changes. Review the ignored prefixes.']}
    if upstream_diff is not None:
        report['evidence']['upstream_diff_sha256']=sha(upstream_diff)
    return report

@dataclass(frozen=True)
class Origin:
    scheme: str
    host: str
    port: int
    allow_loopback: bool

def parse_origin(origin: str, allow_loopback=False) -> Origin:
    if not isinstance(origin,str) or len(origin)>2048 or any(ord(c)<33 or ord(c)>126 for c in origin):
        raise RadarError('INVALID_ORIGIN')
    try:
        p=urlsplit(origin)
        port=p.port or (443 if p.scheme=='https' else 80)
        host=p.hostname
    except ValueError:
        raise RadarError('INVALID_ORIGIN') from None
    if p.username is not None or p.password is not None or p.query or p.fragment or p.path not in ('','/') or not host or p.scheme not in ('http','https') or not 1<=port<=65535:
        raise RadarError('INVALID_ORIGIN')
    try:
        literal=ipaddress.ip_address(host)
    except ValueError:
        literal=None
    loopback=literal is not None and literal.is_loopback
    if p.scheme=='http' and not (allow_loopback and loopback):
        raise RadarError('HTTPS_REQUIRED')
    if literal and not literal.is_global and not (allow_loopback and loopback):
        raise RadarError('PRIVATE_DESTINATION_REFUSED')
    if not literal and not re.fullmatch(r'[A-Za-z0-9](?:[-A-Za-z0-9.]{0,251}[A-Za-z0-9])?',host):
        raise RadarError('INVALID_ORIGIN')
    return Origin(p.scheme,host,port,bool(allow_loopback))

def resolve(origin: Origin):
    try:
        rows=socket.getaddrinfo(origin.host,origin.port,type=socket.SOCK_STREAM)
    except OSError:
        raise RadarError('DESTINATION_UNAVAILABLE') from None
    if not rows:
        raise RadarError('DESTINATION_UNAVAILABLE')
    for family, kind, proto, _, address in rows:
        ip=ipaddress.ip_address(address[0])
        if not ip.is_global and not (origin.allow_loopback and ip.is_loopback):
            raise RadarError('PRIVATE_DESTINATION_REFUSED')
    return rows[0]

class PinnedConnection(http.client.HTTPConnection):
    def __init__(self,origin,timeout):
        super().__init__(origin.host,origin.port,timeout=timeout)
        self.origin=origin
    def connect(self):
        family, kind, proto, _, address=resolve(self.origin)
        raw=socket.socket(family,kind,proto)
        raw.settimeout(self.timeout)
        try:
            raw.connect(address)
            self.sock=ssl.create_default_context().wrap_socket(raw,server_hostname=self.host) if self.origin.scheme=='https' else raw
        except Exception:
            raw.close()
            raise

class ChangeDetectionClient:
    """Fixed-origin, bounded, read-only client. No redirects or ambient proxy use."""
    def __init__(self, origin, api_key, *, allow_loopback=False, timeout=10):
        self.origin=parse_origin(origin,allow_loopback)
        if not isinstance(api_key,str) or not api_key or len(api_key)>512 or any(ord(c)<33 or ord(c)>126 for c in api_key):
            raise RadarError('INVALID_API_KEY')
        if not isinstance(timeout,(int,float)) or isinstance(timeout,bool) or not 0<timeout<=30:
            raise RadarError('INVALID_TIMEOUT')
        self._api_key=api_key
        self.timeout=timeout

    def _get(self,path):
        conn=PinnedConnection(self.origin,self.timeout)
        try:
            conn.request('GET',path,headers={'x-api-key':self._api_key,'Accept':'application/json, text/plain','Accept-Encoding':'identity'})
            response=conn.getresponse()
            if response.status!=200:
                raise RadarError('API_RESPONSE_REFUSED')
            if response.getheader('Content-Encoding','identity').lower() not in ('identity',''):
                raise RadarError('API_ENCODING_REFUSED')
            raw=response.read(MAX_BYTES+1)
            if len(raw)>MAX_BYTES:
                raise RadarError('API_RESPONSE_LIMIT')
            return raw.decode('utf-8')
        except RadarError:
            raise
        except Exception:
            raise RadarError('API_REQUEST_FAILED') from None
        finally:
            conn.close()

    @staticmethod
    def _watch(watch_id):
        if not isinstance(watch_id,str) or not WATCH.fullmatch(watch_id):
            raise RadarError('INVALID_WATCH_ID')
        return watch_id

    def history(self,watch_id):
        data=load_json(self._get('/api/v1/watch/'+self._watch(watch_id)+'/history'))
        if not isinstance(data,dict) or len(data)>2000 or any(not re.fullmatch(r'0|[1-9][0-9]{0,15}',k) for k in data):
            raise RadarError('INVALID_HISTORY')
        # Snapshot paths may reveal server-side file names. They never leave this method.
        return sorted(data,key=int)

    def snapshot(self,watch_id,timestamp):
        if not isinstance(timestamp,str) or not re.fullmatch(r'[0-9]{1,16}|latest',timestamp):
            raise RadarError('INVALID_TIMESTAMP')
        return self._get('/api/v1/watch/'+self._watch(watch_id)+'/history/'+timestamp)

    def difference(self,watch_id,before,after):
        if any(not isinstance(v,str) or not re.fullmatch(r'[0-9]{1,16}',v) for v in (before,after)):
            raise RadarError('INVALID_TIMESTAMP')
        return self._get('/api/v1/watch/'+self._watch(watch_id)+'/difference/'+before+'/'+after+'?format=text')

    def latest_report(self,watch_id,ignore_prefixes=(),include_diff=False):
        history=self.history(watch_id)
        if len(history)<2:
            raise RadarError('INSUFFICIENT_HISTORY')
        before,after=history[-2:]
        a,b=self.snapshot(watch_id,before),self.snapshot(watch_id,after)
        upstream=self.difference(watch_id,before,after)
        result=compare(a,b,ignore_prefixes,include_diff=include_diff,mode='live',upstream_diff=upstream)
        result['evidence']['snapshot_timestamps']=[before,after]
        result['evidence']['watch_sha256']=sha(watch_id)
        return result

def main(argv=None):
    class PrivateParser(argparse.ArgumentParser):
        def error(self,message):
            self.exit(2,'{"error":"INVALID_ARGUMENTS"}\n')
    parser=PrivateParser(description='Sandworm Change Radar / changedetection.io read-only client')
    sub=parser.add_subparsers(dest='command',required=True)
    local=sub.add_parser('compare');local.add_argument('before');local.add_argument('after')
    local.add_argument('--fixture',action='store_true')
    live=sub.add_parser('fetch');live.add_argument('--origin',required=True);live.add_argument('--watch',required=True)
    live.add_argument('--allow-loopback',action='store_true',help='Only for a trusted local changedetection.io server')
    for p in [local,live]:
        p.add_argument('--ignore-prefix',action='append',default=[]);p.add_argument('--include-diff',action='store_true')
    args=parser.parse_args(argv)
    try:
        if args.command=='compare':
            result=compare(read_text(args.before),read_text(args.after),args.ignore_prefix,include_diff=args.include_diff,mode='fixture' if args.fixture else 'import')
        else:
            result=ChangeDetectionClient(args.origin,os.environ.get('CHANGEDETECTION_API_KEY',''),allow_loopback=args.allow_loopback).latest_report(args.watch,args.ignore_prefix,args.include_diff)
        print(json.dumps(result,ensure_ascii=False,indent=2));return 0
    except RadarError as e:
        print(json.dumps({'error':str(e)}),file=sys.stderr);return 1
    except Exception:
        print('{"error":"RADAR_FAILED"}',file=sys.stderr);return 1

if __name__=='__main__':
    raise SystemExit(main())
