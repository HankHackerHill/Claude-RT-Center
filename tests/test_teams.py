import sys,json,tempfile,pathlib; R=pathlib.Path(__file__).resolve().parent.parent; sys.path[:0]=[str(R/"cc")]
import teams as T
p=pathlib.Path(tempfile.mktemp())
p.write_text('{"drill_id":"d","step":"a","technique":"T1595.002","tactic":"Reconnaissance","src_ip":"172.30.0.10","target":"172.30.0.30","tool":"nikto","start_ms":1000,"end_ms":2000}\nnot json\n{"start_ms":5,"end_ms":1}\n{"drill_id":"d","step":"b","technique":"T1190","tactic":"Initial Access","src_ip":"172.30.0.10","target":"172.30.0.20","tool":"curl","start_ms":3000,"end_ms":3500}\n')
steps=T.read_drills(0,p); assert len(steps)==2
q=T.purple_query(steps); json.dumps(q); assert set(q["aggs"]["steps"]["filters"]["filters"])=={"0","1"}
resp={"aggregations":{"steps":{"buckets":{"0":{"doc_count":4,"first":{"value":22000.0},"techniques":{"buckets":[{"key":"T1595","doc_count":4}]},"rules":{"buckets":[]},"rule_ids":{"buckets":[{"key":"100103","doc_count":4}]}},"1":{"doc_count":0,"first":{"value":None}}}}}}
o=T.shape_purple(resp,steps)
assert o[0]["detected"] and o[0]["latency_s"]==21.0 and o[0]["technique_match"], o[0]
assert not o[1]["detected"] and o[1]["latency_s"] is None and not o[1]["technique_match"]
ps='{"Names":"cc-range-suricata-1","Image":"jasonish/suricata:7.0","State":"running","Status":"Up 2h"}\n{"Names":"other","State":"running"}\n'
assert [c["name"] for c in T.parse_docker_ps(ps)]==["cc-range-suricata-1"]
i=T.infra(None); assert "disk" in i and i["indexer"]=="not configured"
print("TEAMS TESTS PASS")
