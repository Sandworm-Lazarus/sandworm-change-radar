"""Exercise installed upstream API resources + Watch storage over loopback HTTP.

This seeds synthetic history, not a crawl. It starts no background scheduler,
browser, notification worker, external watch request or AI request.
"""
import importlib.metadata,json,pathlib,sys,tempfile,threading
from loguru import logger
logger.remove()
from flask import Flask
from flask_restful import Api
from werkzeug.serving import make_server,WSGIRequestHandler
from changedetectionio.store import ChangeDetectionStore
from changedetectionio.api.Watch import WatchHistory,WatchSingleHistory,WatchHistoryDiff
root=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root/'src'))
from change_radar import ChangeDetectionClient

class Quiet(WSGIRequestHandler):
    def log_request(self,*args,**kwargs):pass
    def log_error(self,*args,**kwargs):pass

def main():
    version=importlib.metadata.version('changedetection.io')
    if version!='0.70.3':raise RuntimeError('PINNED_VERSION_REQUIRED')
    with tempfile.TemporaryDirectory(prefix='sandworm-change-smoke-') as temp:
        store=ChangeDetectionStore(datastore_path=temp,include_default_watches=False,version_tag=version)
        settings=store.data['settings']['application']
        settings['api_access_token_enabled']=True
        settings['api_access_token']='synthetic-smoke-only'
        watch_id=store.add_watch('https://example.invalid/synthetic',extras={'paused':True},save_immediately=False)
        watch=store.data['watching'][watch_id]
        watch.save_history_blob('ข่าวเดิม\nรุ่น 1','1700000000','fixture-before')
        watch.save_history_blob('ข่าวใหม่\nรุ่น 2','1700000001','fixture-after')
        app=Flask('sandworm-upstream-api-smoke')
        api=Api(app)
        common={'datastore':store}
        api.add_resource(WatchHistory,'/api/v1/watch/<string:uuid>/history',resource_class_kwargs=common)
        api.add_resource(WatchSingleHistory,'/api/v1/watch/<string:uuid>/history/<string:timestamp>',resource_class_kwargs=common)
        api.add_resource(WatchHistoryDiff,'/api/v1/watch/<string:uuid>/difference/<string:from_timestamp>/<string:to_timestamp>',resource_class_kwargs=common)
        server=make_server('127.0.0.1',0,app,request_handler=Quiet)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            report=ChangeDetectionClient(f'http://127.0.0.1:{server.server_port}','synthetic-smoke-only',allow_loopback=True).latest_report(watch_id)
            assert report['summary']['changed'] is True
            assert report['evidence']['snapshot_timestamps']==['1700000000','1700000001']
            assert 'upstream_diff_sha256' in report['evidence']
            evidence={'schema_version':1,'name':'changedetection.io','version':version,'status':'passed_real_api_resources',
                'scope':'Installed upstream Watch model + datastore + history/snapshot/difference resource classes over local HTTP; synthetic histories seeded directly; full crawler, scheduler, browser and external websites not tested',
                'assertions':{'authenticated_history':'passed','snapshot_text':'passed','upstream_diff':'passed','sandworm_comparison':'passed'},
                'response_evidence':report['evidence']}
            # Random watch UUID is omitted so the published proof contains no server identifiers.
            evidence['response_evidence'].pop('watch_sha256',None)
            (root/'reports/upstream-live.json').write_text(json.dumps(evidence,ensure_ascii=False,indent=2)+'\n')
            print('PASS actual changedetection.io 0.70.3 API resources over loopback; 4 assertions')
        finally:
            server.shutdown();server.server_close();thread.join(timeout=5)

if __name__=='__main__':main()
