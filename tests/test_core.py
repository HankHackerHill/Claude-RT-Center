import sys, json; import pathlib; R=pathlib.Path(__file__).resolve().parent.parent; sys.path[:0]=[str(R/"cc"),str(R/"agents")]
import indexer as I, triage as T
# severity bands
assert [I.severity(x) for x in (0,6,7,11,12,14,15,"x")]==["low","low","medium","medium","high","high","critical","unknown"]
hit={"_id":"a1","_source":{"timestamp":"2026-11-24T10:00:00Z","rule":{"level":12,"id":"100101","description":"d","mitre":{"tactic":["Initial Access"],"id":["T1190"]}},"agent":{"name":"lab"},"data":{"src_ip":"172.30.0.10","dest_ip":"172.30.0.20","http":{"http_user_agent":"x"*999}}}}
n=I.normalize_hit(hit); assert n["src_ip"]=="172.30.0.10" and n["severity"]=="high" and len(n["http_ua"])==300 and n["tactics"]==["Initial Access"]
resp={"hits":{"total":{"value":3},"hits":[hit]},"aggregations":{"by_level":{"buckets":[{"key":"high","doc_count":3}]},"timeline":{"buckets":[{"key":1,"doc_count":3}]},
 "top_rules":{"buckets":[{"key":"d","doc_count":3}]},"tactics":{"buckets":[]},"agents":{"buckets":[]},"src_0":{"buckets":[{"key":"172.30.0.10","doc_count":2}]},"src_1":{"buckets":[{"key":"172.30.0.10","doc_count":1}]},"src_card_0":{"value":1},"src_card_1":{"value":1}}}
s=I.shape_summary(resp,60); assert s["total"]==3 and s["top_sources"]==[{"key":"172.30.0.10","count":3}]
json.dumps(I.summary_query(60,60))
# verdict validation
assert T.validate_verdict({"verdict":"pwned","confidence":2})["verdict"]=="needs_human"
v=T.validate_verdict({"verdict":"true_positive","confidence":0.9,"attack_stage":"recon","summary":"s","evidence":["a"]*20,"recommended_actions":"rm -rf"})
assert v["verdict"]=="true_positive" and len(v["evidence"])==10 and v["recommended_actions"]==[]
# tool arg validation (no indexer needed for bad IP path)
assert "bad arguments" in T.run_tool(None,"related_alerts",{"src_ip":"1.1.1.1\" OR *"})
assert json.loads(T.run_tool(None,"asset_lookup",{"ip":"172.30.0.20"}))["name"]=="juice-shop"
# agent loop with mocked model + indexer
class FakeIx:
    def search(self,b): return {"hits":{"total":{"value":1},"hits":[hit]},"aggregations":{}}
calls=[]
def fake_claude(k,m,msgs):
    calls.append(msgs)
    if len(calls)==1: return {"stop_reason":"tool_use","content":[{"type":"tool_use","id":"t1","name":"related_alerts","input":{"src_ip":"172.30.0.10"}}]}
    assert msgs[-1]["content"][0]["type"]=="tool_result" and "172.30.0.10" in msgs[-1]["content"][0]["content"]
    return {"stop_reason":"end_turn","content":[{"type":"text","text":'Here: {"verdict":"benign_true_positive","confidence":0.9,"attack_stage":"initial_access","summary":"drill"}'}]}
T.call_claude=fake_claude
r=T.triage_alert(FakeIx(),"k","m",n); assert r["verdict"]=="benign_true_positive", r
print("ALL TESTS PASS")
