"""Local-only Flask service for the synthetic awareness and TI demo."""
import csv, json, os, sqlite3, sys
from pathlib import Path
import tempfile
from flask import Flask, jsonify, request, send_from_directory
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from services import validate_indicator, enrich_indicator, correlate
DATA = ROOT / "data/threat_intelligence_dataset.csv"
DB_PATH = Path(tempfile.gettempdir()) / "signaldesk-dashboard.sqlite3" if os.getenv("VERCEL") else ROOT / "data/dashboard.sqlite3"
app = Flask(__name__, static_folder=str(ROOT / "frontend"), static_url_path="")

def records():
    with DATA.open(encoding="utf-8", newline="") as f: return list(csv.DictReader(f))
def db_init():
    with sqlite3.connect(DB_PATH) as db:
        db.execute("CREATE TABLE IF NOT EXISTS quiz_results(id INTEGER PRIMARY KEY, score INTEGER, total INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP)")
        db.execute("CREATE TABLE IF NOT EXISTS alert_status(alert_id TEXT PRIMARY KEY, status TEXT)")
        db.execute("CREATE TABLE IF NOT EXISTS analyst_notes(id INTEGER PRIMARY KEY, threat_id TEXT, note TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)")
db_init()
@app.get("/")
def home(): return send_from_directory(ROOT / "frontend", "index.html")
@app.get("/api/dashboard/stats")
@app.get("/api/stats")
def stats():
    rows=records(); categories={}; severity={s:0 for s in ("INFORMATIONAL","LOW","MEDIUM","HIGH","CRITICAL")}
    for r in rows: categories[r["threat_category"]]=categories.get(r["threat_category"],0)+1; severity[r["severity"]]=severity.get(r["severity"],0)+1
    return jsonify({"observations":len(rows),"indicators":len({r['indicator_value'] for r in rows}),"alerts":len(correlate(rows)),"cves":sum(r["indicator_type"]=="CVE ID" for r in rows),"severity_counts":severity,"category_counts":categories,"recent":rows[:8],"record_label":"SYNTHETIC / DEMO ONLY","confirmed_incidents":0})
@app.get("/api/threats")
def threats():
    rows=records(); q=request.args.get("q","").strip().lower(); cat=request.args.get("category","").upper(); sev=request.args.get("severity","").upper()
    selected=[r for r in rows if (not q or q in json.dumps(r).lower()) and (not cat or r["threat_category"]==cat) and (not sev or r["severity"]==sev)]
    return jsonify({"items":selected[:250],"total":len(selected),"limit":250})
@app.get("/api/threats/<tid>")
def detail(tid):
    row=next((r for r in records() if r["threat_id"]==tid),None)
    if not row: return jsonify({"error":"Observation not found"}),404
    row["record_type"]="OBSERVATION"; row["incident_notice"]="This observation is not a confirmed incident."
    with sqlite3.connect(DB_PATH) as db: row["notes"]=[{"note":x[0],"created_at":x[1]} for x in db.execute("SELECT note,created_at FROM analyst_notes WHERE threat_id=?",(tid,))]
    return jsonify(row)
@app.post("/api/threats/<tid>/notes")
def add_note(tid):
    body=request.get_json(silent=True) or {}; note=str(body.get("note","")).strip()
    if not any(r["threat_id"]==tid for r in records()): return jsonify({"error":"Observation not found"}),404
    if not note or len(note)>1000: return jsonify({"error":"Note must contain 1-1000 characters"}),400
    with sqlite3.connect(DB_PATH) as db: db.execute("INSERT INTO analyst_notes(threat_id,note) VALUES (?,?)",(tid,note))
    return jsonify({"saved":True}),201
@app.get("/api/indicators/search")
def search():
    value=request.args.get("q","")
    if not value: return jsonify({"error":"Supply q"}),400
    return jsonify(enrich_indicator(value,records()))
@app.get("/api/dashboard/trends")
def trends():
    by={}
    for r in records(): by[r["first_seen"][:7]]=by.get(r["first_seen"][:7],0)+1
    return jsonify([{"month":k,"observations":v} for k,v in sorted(by.items())])
@app.get("/api/alerts")
def alerts():
    rows=correlate(records())
    with sqlite3.connect(DB_PATH) as db: status=dict(db.execute("SELECT alert_id,status FROM alert_status"))
    for a in rows: a["status"]=status.get(a["alert_id"],a["status"])
    return jsonify(rows)
@app.put("/api/alerts/<aid>/status")
def update_alert(aid):
    status=(request.get_json(silent=True) or {}).get("status")
    if status not in {"NEW","UNDER_REVIEW","MONITORING","CLOSED","FALSE_POSITIVE"}: return jsonify({"error":"Unsupported status"}),400
    if aid not in {a["alert_id"] for a in correlate(records())}: return jsonify({"error":"Alert not found"}),404
    with sqlite3.connect(DB_PATH) as db: db.execute("INSERT INTO alert_status VALUES (?,?) ON CONFLICT(alert_id) DO UPDATE SET status=excluded.status",(aid,status))
    return jsonify({"alert_id":aid,"status":status})
@app.get("/api/vulnerabilities")
def vulnerabilities(): return jsonify([r for r in records() if r["indicator_type"]=="CVE ID"][:200])
@app.get("/api/awareness/modules")
def modules(): return jsonify(json.loads((ROOT/"awareness/modules.json").read_text(encoding="utf-8")))
@app.get("/api/quiz")
def quiz(): return jsonify([{k:v for k,v in q.items() if k!="answer"} for q in json.loads((ROOT/"awareness/quiz_questions.json").read_text(encoding="utf-8"))])
@app.post("/api/quiz/submit")
def submit_quiz():
    body=request.get_json(silent=True) or {}; qs=json.loads((ROOT/"awareness/quiz_questions.json").read_text(encoding="utf-8")); ans=body.get("answers",[])
    if not isinstance(ans,list) or len(ans)!=len(qs): return jsonify({"error":f"Submit exactly {len(qs)} answers"}),400
    correct=sum(str(a)==str(q["answer"]) for a,q in zip(ans,qs)); score=round(100*correct/len(qs))
    with sqlite3.connect(DB_PATH) as db: db.execute("INSERT INTO quiz_results(score,total) VALUES (?,?)",(score,len(qs)))
    return jsonify({"score":score,"correct":correct,"total":len(qs),"recommendation":"Review the lessons and retry." if score<80 else "Good work. Keep reporting suspicious activity through your approved channel."})
@app.get("/api/awareness/score")
def awareness_score():
    with sqlite3.connect(DB_PATH) as db: rs=db.execute("SELECT score,total,created_at FROM quiz_results ORDER BY id DESC LIMIT 20").fetchall()
    return jsonify({"attempts":len(rs),"latest_score":rs[0][0] if rs else None,"average_score":round(sum(r[0] for r in rs)/len(rs)) if rs else None,"history":[{"score":r[0],"total":r[1],"created_at":r[2]} for r in rs]})
if __name__=="__main__":
    db_init()
    if not DATA.exists():
        sys.path.insert(0,str(ROOT/"data")); from generate_threat_data import generate; generate()
    app.run(host=os.getenv("HOST","127.0.0.1"),port=int(os.getenv("PORT","5000")),debug=False)
