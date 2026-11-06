import json
import tempfile
import pathlib
import re
import urllib.parse
from lupa.luajit21 import LuaRuntime

DELIVERY=pathlib.Path(__file__).resolve().parents[2] / 'configs/openresty'
lua=LuaRuntime(unpack_returned_tuples=True)
target='example.portal.queryList'
path='/business-api/gateway'
guard=lua.execute('return function()\n'+(DELIVERY/'query_portal_guard.lua').read_text(encoding='utf-8')+'\nend')

def table(value):
    if isinstance(value,dict):return lua.table_from({k:table(v) for k,v in value.items()})
    if isinstance(value,list):return lua.table_from([table(v) for v in value])
    if value is None:return lua.eval('function() return function() end end')()
    return value

def decode(text):
    try:return table(json.loads(text))
    except (ValueError,TypeError):return None,'invalid json'

lua.globals()['decode_for_test']=decode
lua.execute('package.preload["cjson.safe"] = function() return {decode=decode_for_test} end')

def match(text,pattern,flags):
    found=re.search(pattern,text,re.I)
    return (found.start()+1,found.end(),None) if found else (None,None,None)

def run(body,uri=path,original=None,method='POST',filename=None,encoding=None,content_length=None):
    state={'read_body':0,'logs':[]}
    def read_body():state['read_body']+=1
    def log(*args):state['logs'].append(' '.join(str(x) for x in args))
    req=lua.table_from({'get_method':lambda:method,'read_body':read_body,'get_body_data':lambda:body,'get_body_file':lambda:filename})
    var=lua.table_from({'uri':uri,'request_uri':original if original is not None else uri})
    if content_length is not None:var['content_length']=str(content_length)
    if encoding is not None:var['http_content_encoding']=encoding
    lua.globals()['ngx']=lua.table_from({'var':var,'req':req,'re':lua.table_from({'find':match}),'unescape_uri':urllib.parse.unquote,'log':log,'exit':lambda status:status,'ERR':3,'WARN':4})
    status=guard()
    return status if status is not None else 'continue',state

def doc(value,method=target):
    return json.dumps({'head':{'method':method},'body':{'container_type':value}},ensure_ascii=False)

tests=[]
def check(name,expected,body,**kwargs):
    result,state=run(body,**kwargs)
    passed=result==expected
    tests.append({'name':name,'expected':expected,'actual':result,'passed':passed})
    assert passed,(name,result,expected)

for value in (0,1,2,3,'1','2','2147483647',''):
    check('normal_numeric_'+repr(value),'continue',doc(value))
check('optional_missing','continue',json.dumps({'head':{'method':target},'body':{}}))
for value in ('1 OR 1=1',"1' minus select chr(1/0) from dual",'UTL_INADDR.GET_HOST_ADDRESS(x)','1%27','１',-1,1.2,True,{},[],None,'9999999999'):
    check('invalid_parameter_'+type(value).__name__+'_'+str(value)[:24],403,doc(value))
check('json_unicode_escape',403,'{"head":{"method":"'+target+'"},"body":{"container_type":"1\\u0027 minus select chr(1/0) from dual"}}')
check('encoded_json_key',403,'{"head":{"method":"'+target+'"},"body":{"container_\\u0074ype":"bad"}}')
check('unrelated_method','continue',doc('arbitrary normal business text',method='example.user.queryInfo'))
check('unrelated_path','continue',doc('bad'),uri='/somewhere/else')
check('semicolon_context',403,doc('bad'),uri='/business-api;jsessionid=x/gateway')
check('gateway_suffix',403,doc('bad'),uri=path+';x=1')
check('rewritten_uri_original_is_checked',403,doc('bad'),uri='/gateway',original=path)
check('encoded_original_path',403,doc('bad'),uri='/gateway',original='/x/../business-api/%67ateway')
check('get_body_without_content_length',403,doc('bad'),method='GET')
check('bodyless_get','continue',None,method='GET')
check('bodyless_options','continue',None,method='OPTIONS')
check('invalid_json',400,'not-json')
check('compressed_request',415,doc(1),encoding='gzip')
check('declared_oversize',413,doc(1),content_length=1024*1024+1)
check('actual_oversize',413,' '* (1024*1024+1))
with tempfile.TemporaryDirectory(prefix='sql-guard-') as directory:
    tmp=pathlib.Path(directory)/'request-body.temp'
    tmp.write_text(doc('bad'),encoding='utf-8')
    check('disk_buffered_body',403,None,filename=tmp.as_posix())
    check('unreadable_body_file',500,None,filename=(tmp.parent/'does-not-exist.temp').as_posix())
print(json.dumps({'scope':'LuaJIT with mocked ngx/cjson; no OpenResty integration', 'passed':len(tests)}))
