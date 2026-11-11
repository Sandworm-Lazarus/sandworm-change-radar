import importlib.util,json,pathlib,socket,sys,threading,unittest
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from change_radar import *
WATCH_ID='095be615-a8ad-4c33-8e9c-c7612fbf6c9f'

class CoreTests(unittest.TestCase):
    def test_change_blocks(self):
        r=compare('ราคา 10\nพร้อมขาย','ราคา 12\nพร้อมขาย');self.assertEqual(r['summary']['change_blocks'],1)
    def test_raw_content_omitted(self):
        r=compare('PRIVATE_OLD','PRIVATE_NEW');self.assertNotIn('PRIVATE',json.dumps(r))
    def test_explicit_diff(self):
        self.assertEqual(compare('old','new',include_diff=True)['findings'][0]['after'],['new'])
    def test_ignore_literal(self):
        self.assertFalse(compare('Updated: 1\nข่าว','Updated: 2\nข่าว',['Updated:'])['summary']['changed'])
    def test_nfc(self):
        self.assertFalse(compare('e\u0301','é')['summary']['changed'])
    def test_input_exact_hash(self):
        r=compare('abc\r\n','abc\n');self.assertNotEqual(r['evidence']['before_sha256'],r['evidence']['after_sha256'])
    def test_limits(self):
        with self.assertRaisesRegex(RadarError,'LIMIT'):normalize('x'*(MAX_BYTES+1))
        with self.assertRaisesRegex(RadarError,'LINE_LIMIT'):normalize('x\n'*(MAX_LINES+1))
    def test_ignore_limit(self):
        for values in [[''],['\n'],['a']*17]:
            with self.assertRaises(RadarError):normalize('x',values)
    def test_duplicate_json_rejected(self):
        with self.assertRaisesRegex(RadarError,'DUPLICATE'):load_json('{"1":"x","1":"y"}')
    def test_nan_rejected(self):
        with self.assertRaisesRegex(RadarError,'INVALID_JSON'):load_json('{"x":NaN}')
    def test_untrusted_watch(self):
        for w in ['../history','x\r\nx-api-key: private','latest','00000000%2f']:
            with self.assertRaisesRegex(RadarError,'INVALID_WATCH'):ChangeDetectionClient._watch(w)
    def test_origin_credentials_query_path_reject(self):
        for origin in ['https://user:pass@example.com','https://example.com/a','https://example.com?token=secret','https://example.com#x','https://example.com\n','ftp://example.com']:
            with self.assertRaises(RadarError):parse_origin(origin)
    def test_http_loopback_explicit(self):
        with self.assertRaises(RadarError):parse_origin('http://127.0.0.1:5000')
        self.assertEqual(parse_origin('http://127.0.0.1:5000',True).port,5000)
    def test_private_network_blocked(self):
        for origin in ['https://10.0.0.1','https://169.254.169.254','https://[::1]']:
            with self.assertRaisesRegex(RadarError,'PRIVATE'):parse_origin(origin)
    def test_dns_private_and_mixed_refused(self):
        origin=parse_origin('https://example.com')
        rows=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('93.184.216.34',443)),(socket.AF_INET,socket.SOCK_STREAM,6,'',('127.0.0.1',443))]
        with patch('socket.getaddrinfo',return_value=rows):
            with self.assertRaisesRegex(RadarError,'PRIVATE'):resolve(origin)
    def test_api_key_newline_reject(self):
        with self.assertRaisesRegex(RadarError,'API_KEY'):ChangeDetectionClient('https://example.com','secret\n')
    def test_timestamp_path_reject(self):
        c=ChangeDetectionClient('https://example.com','test')
        with self.assertRaisesRegex(RadarError,'TIMESTAMP'):c.snapshot(WATCH_ID,'../secret')
    def test_history_paths_not_exported(self):
        c=ChangeDetectionClient('https://example.com','test')
        with patch.object(c,'_get',return_value='{"10":"PRIVATE_SERVER_PATH","2":"PRIVATE_OTHER_PATH"}'):
            self.assertEqual(c.history(WATCH_ID),['2','10'])
    def test_invalid_mode(self):
        with self.assertRaisesRegex(RadarError,'MODE'):compare('a','b',mode='fake')
    def test_ambiguous_timestamp_identity(self):
        c=ChangeDetectionClient('https://example.com','test')
        with patch.object(c,'_get',return_value='{"01":"x","1":"y"}'):
            with self.assertRaisesRegex(RadarError,'HISTORY'):c.history(WATCH_ID)

class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.headers.get('x-api-key')!='test-only':self.send_response(401);self.end_headers();return
                if self.path.endswith('/history'):body=b'{"1":"/private/a","2":"/private/b"}'
                elif self.path.endswith('/history/1'):body='ข่าวเก่า'.encode()
                elif self.path.endswith('/history/2'):body='ข่าวใหม่'.encode()
                elif '/difference/' in self.path:body=b'upstream diff fixture'
                elif self.path.endswith('/history/3'):body=b'x'*(MAX_BYTES+2)
                elif self.path.endswith('/history/4'):
                    self.send_response(302);self.send_header('Location','https://example.com/private');self.end_headers();return
                else:self.send_response(500);self.end_headers();self.wfile.write(b'PRIVATE_SERVER_FAILURE');return
                self.send_response(200);self.end_headers();self.wfile.write(body)
            def log_message(self,*args):pass
        cls.server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()
        cls.origin=f'http://127.0.0.1:{cls.server.server_port}'
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.thread.join()
    def client(self,key='test-only'):
        return ChangeDetectionClient(self.origin,key,allow_loopback=True)
    def test_upstream_api_contract_roundtrip(self):
        r=self.client().latest_report(WATCH_ID)
        self.assertEqual(r['summary']['change_blocks'],1)
        self.assertEqual(r['evidence']['snapshot_timestamps'],['1','2'])
        self.assertIn('upstream_diff_sha256',r['evidence'])
        serialized=json.dumps(r);self.assertNotIn('/private/',serialized);self.assertNotIn('test-only',serialized)
    def test_wrong_auth_sanitized(self):
        with self.assertRaisesRegex(RadarError,'^API_RESPONSE_REFUSED$'):self.client('PRIVATE_TOKEN').history(WATCH_ID)
    def test_response_limit(self):
        with self.assertRaisesRegex(RadarError,'^API_RESPONSE_LIMIT$'):self.client().snapshot(WATCH_ID,'3')
    def test_redirect_refused(self):
        with self.assertRaisesRegex(RadarError,'^API_RESPONSE_REFUSED$'):self.client().snapshot(WATCH_ID,'4')
    def test_upstream_body_never_errors(self):
        with self.assertRaisesRegex(RadarError,'^API_RESPONSE_REFUSED$'):self.client().snapshot(WATCH_ID,'5')
    def test_insufficient_history(self):
        c=self.client()
        with patch.object(c,'history',return_value=['1']):
            with self.assertRaisesRegex(RadarError,'INSUFFICIENT'):c.latest_report(WATCH_ID)

if __name__=='__main__':unittest.main()
