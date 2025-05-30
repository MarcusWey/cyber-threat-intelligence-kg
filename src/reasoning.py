from rdflib import Graph
from owlrl import DeductiveClosure, OWLRL_Semantics

DATA_PATH = "data/combined.ttl"
ONTO_PATH = "data/cti.owl"
OUTPUT_PATH = "data/reasoned_graph.ttl"

g = Graph()
g.parse(DATA_PATH, format="turtle")
g.parse(ONTO_PATH, format="xml")

print(f"Initial graph: {len(g)} triples. Running reasoning...")
DeductiveClosure(OWLRL_Semantics).expand(g)
print(f"After reasoning: {len(g)} triples.")

g.serialize(destination=OUTPUT_PATH, format="turtle")
print(f"Reasoning complete. OWL RL graph saved to {OUTPUT_PATH} ({len(g)} triples).")
