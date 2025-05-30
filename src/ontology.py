from owlready2 import *
import os

# Create ontology 
onto = get_ontology("http://tswgroup41.org/cti#")

with onto:
    # Core CTI classes
    class ThreatActor(Thing): pass
    class Campaign(Thing): pass
    class Technique(Thing): pass
    class Tactic(Thing): pass
    class Indicator(Thing): pass
    class Vulnerability(Thing): pass
    class Tool(Thing): pass

    # Object properties
    class hasTactic(ObjectProperty):
        domain = [Technique]
        range  = [Tactic]

    class usesTechnique(ObjectProperty):
        domain = [ThreatActor, Campaign]
        range  = [Technique]

    class hasIndicator(ObjectProperty):
        domain = [Campaign]
        range  = [Indicator]

    class linkedTo(ObjectProperty):
        domain = [Campaign]
        range  = [Campaign]
        symmetric = True

    # Data properties
    class name(DataProperty, FunctionalProperty): pass
    class description(DataProperty): pass
    class hasATTCKID(DataProperty, FunctionalProperty): pass

    # Example SWRL rule: link campaigns that share an indicator
    rule = Imp()
    rule.set_as_rule("""
        Campaign(?c1), Campaign(?c2), Indicator(?i),
        hasIndicator(?c1, ?i), hasIndicator(?c2, ?i), differentFrom(?c1, ?c2)
         -> linkedTo(?c1, ?c2)
    """)

# Save ontology
out_path = "data/cti.owl"
os.makedirs("data", exist_ok=True)
onto.save(file=out_path, format="rdfxml")
print(f"Ontology saved to {out_path}")
