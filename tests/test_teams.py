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
# ---- v4: exact attribution (markers + non-overlapping packet windows) ----
mk=lambda i,s,e,src="172.30.0.10",m=None:{"step":f"s{i}","technique":"T1190","src_ip":src,"start_ms":s,"end_ms":e,"marker":m}
st=[mk(1,1000,1400),mk(2,1450,1800,m="cc-step/d-s2"),mk(3,1850,9000,m="cc-step/d-s3")]
w=T.packet_windows(st)
assert all(w[i][1] < w[i+1][0] for i in range(len(w)-1)), w          # never overlap
assert w[0][0]==1000-T.PACKET_SLACK_MS and w[2][1]==9000+T.PACKET_SLACK_MS and not any(x[2] for x in w)
assert w[0][1]==1425 and w[1][0]==1426                                # clipped at the gap midpoint
# concurrent steps from one source -> ambiguous; other sources unaffected
w2=T.packet_windows([mk(1,1000,5000),mk(2,2000,3000),mk(3,2000,3000,src="172.30.0.11")])
assert w2[0][2] and w2[1][2] and not w2[2][2]
# marker validation: only harness-shaped markers are used in a query
assert T.valid_marker("cc-step/drill-20261125T183619Z-s2") and not T.valid_marker("cc-step/*") and not T.valid_marker("x") and not T.valid_marker(None)
f=json.dumps(T.step_filter(st[1],w[1])); assert '"*cc-step/d-s2"' in f and '"*cc-step/d-s2*"' not in f and "data.timestamp" in f and "data.flow.src_ip" in f
f0=json.dumps(T.step_filter(st[0],w[0])); assert "cc-step/d-" not in f0 and '"*cc-step/*"' in f0  # unmarked step: window only, excludes marked alerts
bad=dict(st[1],marker="cc-step/*"); assert "*cc-step/**" not in json.dumps(T.step_filter(bad))      # wildcard injection ignored
q=T.purple_query(st); assert set(q["aggs"]["steps"]["filters"]["filters"])=={"0","1","2"}
r={"aggregations":{"steps":{"buckets":{"1":{"doc_count":2,"by_marker":{"doc_count":2},"first":{"value":2450.0},"techniques":{"buckets":[{"key":"T1190","doc_count":2}]}}}}}}
o=T.shape_purple(r,st); assert o[1]["alerts_by_marker"]==2 and o[1]["marker"]=="cc-step/d-s2" and o[1]["latency_s"]==1.0 and not o[0]["detected"]
# review fixes: marker anchored at the end of the UA (s1 must not match s10); overlap vs a long earlier step
import fnmatch
pat=T._has_marker("cc-step/d-s1")["wildcard"]["data.http.http_user_agent"]["value"]
assert fnmatch.fnmatchcase("Mozilla/5.0 (X11) cc-step/d-s1",pat) and not fnmatch.fnmatchcase("Mozilla/5.0 (X11) cc-step/d-s10",pat)
w3=T.packet_windows([mk(1,1000,9000),mk(2,2000,3000),mk(3,4000,5000)])     # step 1 spans 2 AND 3
assert w3[0][2] and w3[1][2] and w3[2][2], w3
w4=T.packet_windows([mk(1,1000,2000),mk(2,2100,2200),mk(3,2300,2400)])     # sequential: none ambiguous, no overlap
assert not any(x[2] for x in w4) and w4[0][1]<w4[1][0] and w4[1][1]<w4[2][0]
print("TEAMS v4 ATTRIBUTION TESTS PASS")
