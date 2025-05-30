import os
import json
from rdflib import Graph, Namespace, RDF, Literal
from rdflib.namespace import OWL, RDFS

CTI = Namespace("http://tswgroup41.org/cti#")

TYPE_MAP = {
    "intrusion-set": "ThreatActor",
    "malware": "Malware",
    "tool": "Tool",
    "attack-pattern": "Technique",
    "campaign": "Campaign"
}

g = Graph()
g.bind("cti", CTI)
g.bind("rdf", RDF)
g.bind("owl", OWL)
g.bind("rdfs", RDFS)

base_path = os.path.join("data", "cti", "enterprise-attack")

ENTITY_FOLDERS = [
    "intrusion-set",
    "malware",
    "tool",
    "attack-pattern",
    "campaign"
]

# Process entities
for folder in ENTITY_FOLDERS:
    label = TYPE_MAP[folder]
    ent_dir = os.path.join(base_path, folder)
    if not os.path.isdir(ent_dir):
        print(f"⚠ Folder not found: {ent_dir}")
        continue
    for fname in os.listdir(ent_dir):
        if not fname.endswith(".json"):
            continue
        with open(os.path.join(ent_dir, fname), encoding="utf-8") as f:
            try:
                data = json.load(f)
            except Exception as e:
                print(f"⚠ Could not load {fname}: {e}")
                continue
            # Sometimes it's a bundle, sometimes a single object
            objects = data["objects"] if isinstance(data, dict) and "objects" in data else [data]
            for obj in objects:
                obj_type = obj.get("type")
                obj_id = obj.get("id", "").split("--")[-1]
                if obj_type != folder or not obj_id:
                    continue
                entity_uri = CTI[f"{label}_{obj_id}"]
                g.add((entity_uri, RDF.type, CTI[label]))
                # Add the human-readable name!
                name = obj.get("name")
                if name:
                    g.add((entity_uri, CTI.name, Literal(name)))
                else:
                    # For rare cases with no name, fallback to ID for debug/visualization
                    g.add((entity_uri, CTI.name, Literal(obj_id)))
                # Optionally: external references (like mitre-attack IDs)
                for ext in obj.get("external_references", []):
                    external_id = ext.get("external_id")
                    if external_id:
                        g.add((entity_uri, CTI.hasATTCKID, Literal(external_id)))
                    url = ext.get("url")
                    if url:
                        g.add((entity_uri, CTI.external_reference, Literal(url)))

# Load relationships 
rel_dir = os.path.join(base_path, "relationship")
uses_count = 0
indicates_count = 0

if os.path.isdir(rel_dir):
    for fname in os.listdir(rel_dir):
        if not fname.endswith(".json"):
            continue
        with open(os.path.join(rel_dir, fname), encoding="utf-8") as f:
            try:
                content = json.load(f)
            except Exception as e:
                print(f"⚠ Could not load {fname}: {e}")
                continue
            objs = content["objects"] if isinstance(content, dict) and "objects" in content else [content]
            for data in objs:
                if data.get("type") != "relationship":
                    continue
                rtype = data.get("relationship_type", "")
                src_ref = data.get("source_ref")
                tgt_ref = data.get("target_ref")
                if not src_ref or "--" not in src_ref or not tgt_ref or "--" not in tgt_ref:
                    continue
                src_type, src_id = src_ref.split("--", 1)
                tgt_type, tgt_id = tgt_ref.split("--", 1)
                if src_type not in TYPE_MAP or tgt_type not in TYPE_MAP:
                    continue
                subj = CTI[f"{TYPE_MAP[src_type]}_{src_id}"]
                obj  = CTI[f"{TYPE_MAP[tgt_type]}_{tgt_id}"]
                if rtype == "uses":
                    g.add((subj, CTI.usesTechnique, obj))
                    uses_count += 1
                elif rtype == "indicates":
                    g.add((subj, CTI.hasIndicator, obj))
                    indicates_count += 1

# Save to TTL
output_path = os.path.join("data", "combined.ttl")
os.makedirs(os.path.dirname(output_path), exist_ok=True)
g.serialize(output_path, format="turtle")

# Final summary
print(f"Ingested data with {len(g)} total triples.")
print(f"usesTechnique relationships added: {uses_count}")
print(f"hasIndicator relationships added: {indicates_count}")
print(f"Output saved to {output_path}")

missing = []
for s, p, o in g.triples((None, RDF.type, None)):
    if (s, CTI.name, None) not in g:
        missing.append(str(s))
if missing:
    print("WARNING: The following entities are missing names:", missing[:10], "...")
else:
    print("All entities have names.")
