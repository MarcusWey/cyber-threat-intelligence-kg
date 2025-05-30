# src/app.py
from flask import Flask, request, jsonify
from flask_cors import CORS
from rdflib import Graph, Namespace, URIRef
import logging
import sys

app = Flask(__name__)
CORS(app)

# where you saved your combined TTL
DATA_PATH = "data/combined.ttl"
CTI = Namespace("http://tswgroup41.org/cti#")

# enable server-side logging
logging.basicConfig(level=logging.INFO)

def load_graph():
    g = Graph()
    g.parse(DATA_PATH, format="turtle")
    return g

@app.errorhandler(Exception)
def handle_exception(e):
    import traceback
    traceback.print_exc(file=sys.stderr)
    return jsonify(error=str(e)), 500

@app.route("/actors", methods=["GET"])
def get_actors():
    g = load_graph()
    q = """
      PREFIX cti: <http://tswgroup41.org/cti#>
      SELECT DISTINCT ?actor ?name WHERE {
        ?actor a cti:ThreatActor ;
               cti:name ?name .
      } ORDER BY ?name
    """
    results = g.query(q)
    out = [{"name": str(name), "uri": str(actor)} for actor, name in results]
    logging.info(f"/actors → {len(out)} rows")
    return jsonify(out)

@app.route("/actor_profile", methods=["GET"])
def actor_profile():
    nm = request.args.get("name")
    if not nm:
        return jsonify(error="Missing name parameter"), 400
    g = load_graph()
    q = f"""
      PREFIX cti: <http://tswgroup41.org/cti#>
      SELECT ?tech ?tech_name ?tool ?tool_name WHERE {{
        ?actor a cti:ThreatActor ;
               cti:name "{nm}" ;
               cti:usesTechnique ?tech .
        OPTIONAL {{ ?tech cti:name ?tech_name. }}
        OPTIONAL {{
          ?tech cti:usesTechnique ?tool .
          OPTIONAL {{ ?tool cti:name ?tool_name. }}
        }}
      }}
    """
    rows = g.query(q)
    out = []
    for row in rows:
        out.append({
            "tech": str(row.tech),
            "tech_name": str(row.tech_name) if row.tech_name else "",
            "tool": str(row.tool) if row.tool else "",
            "tool_name": str(row.tool_name) if row.tool_name else ""
        })
    logging.info(f"/actor_profile({nm}) → {len(out)} rows")
    return jsonify(out)

@app.route("/campaigns", methods=["GET"])
def get_campaigns():
    g = load_graph()
    q = """
      PREFIX cti: <http://tswgroup41.org/cti#>
      SELECT DISTINCT ?camp ?name WHERE {
        ?camp a cti:Campaign ;
              cti:name ?name .
      } ORDER BY ?name
    """
    results = g.query(q)
    out = [{"name": str(name), "uri": str(c)} for c, name in results]
    logging.info(f"/campaigns → {len(out)} rows")
    return jsonify(out)

@app.route("/campaign_profile", methods=["GET"])
def campaign_profile():
    nm = request.args.get("name")
    if not nm:
        return jsonify(error="Missing name parameter"), 400
    g = load_graph()
    q = f"""
      PREFIX cti: <http://tswgroup41.org/cti#>
      SELECT ?tech ?tech_name ?tool ?tool_name WHERE {{
        ?camp a cti:Campaign ;
              cti:name "{nm}" ;
              cti:usesTechnique ?tech .
        OPTIONAL {{ ?tech cti:name ?tech_name. }}
        OPTIONAL {{
          ?tech cti:usesTechnique ?tool .
          OPTIONAL {{ ?tool cti:name ?tool_name. }}
        }}
      }}
    """
    rows = g.query(q)
    out = []
    for row in rows:
        out.append({
            "tech": str(row.tech),
            "tech_name": str(row.tech_name) if row.tech_name else "",
            "tool": str(row.tool) if row.tool else "",
            "tool_name": str(row.tool_name) if row.tool_name else ""
        })
    logging.info(f"/campaign_profile({nm}) → {len(out)} rows")
    return jsonify(out)

@app.route("/top-techniques", methods=["GET"])
def top_techniques():
    g = load_graph()
    # manually count usesTechnique triples
    counts = {}
    for _, _, tech in g.triples((None, CTI.usesTechnique, None)):
        u = str(tech)
        counts[u] = counts.get(u, 0) + 1
    # take top 5
    top5 = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:5]
    out = []
    for tech_uri, cnt in top5:
        # look up its name (if any)
        nm = ""
        for _, _, lit in g.triples((URIRef(tech_uri), CTI.name, None)):
            nm = str(lit)
            break
        out.append({"tech": tech_uri, "name": nm, "count": cnt})
    logging.info(f"/top-techniques → {len(out)} rows")
    return jsonify(out)

@app.route("/sparql", methods=["POST"])
def sparql_query():
    data = request.get_json() or {}
    q = data.get("query", "")
    if not q:
        return jsonify(error="Missing query parameter"), 400
    g = load_graph()
    results = g.query(q)
    out = [{k: str(v) for k, v in row.asdict().items()} for row in results]
    return jsonify(out)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
