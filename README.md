# Cyber Threat Intelligence Knowledge Graph

## Overview

This project implements a Cyber Threat Intelligence (CTI) Knowledge Graph using Semantic Web technologies. The pipeline transforms structured cyber threat data into RDF triples, applies a custom OWL ontology to model domain knowledge, performs OWL RL reasoning to infer implicit relationships, and provides a SPARQL endpoint for querying the knowledge graph. An interactive D3.js front end enables visual exploration and analysis of attack actors, campaigns, and techniques.

## Features

- **RDF Data Modeling:** Converts CTI data (e.g., STIX JSON) into standard RDF triples.
- **OWL Ontology:** Models threat actors, campaigns, techniques, and tooling with classes and properties in OWL2.
- **OWL RL Reasoning:** Uses rule-based inference to add hidden links and enrich the knowledge graph with implied knowledge.
- **SPARQL API:** Exposes a RESTful Flask backend supporting flexible SPARQL 1.1 queries over the knowledge graph.
- **Interactive Visualization:** D3.js front end displays the knowledge graph, with zoom/pan, node highlighting, tabbed views (actor/campaign/technique-centric), and responsive layout.
- **End-to-End Semantic Pipeline:** Fully integrated workflow from raw data ingestion to web-based visualization.

## Project Structure

- `data/` — Raw CTI source files, generated RDF/OWL (e.g., `combined.ttl`, `cti.owl`, `reasoned_graph.ttl`)
- `src/` — Python scripts:
    - `ingest.py` — Convert structured JSON data to RDF triples
    - `ontology.py` — Define and serialize the OWL domain ontology
    - `reasoning.py` — Apply OWL RL reasoning for inference
    - `app.py` — Flask backend providing the SPARQL API
- `ui/` — Front end:
    - `index.html` — User interface and instructions
    - `js/graph.js` — D3.js-based graph rendering and UX logic

## Tools and Dependencies

| Library     | Purpose                                               |
|-------------|-------------------------------------------------------|
| rdflib      | RDF graph management and SPARQL queries               |
| owlready2   | Define/load OWL ontologies                            |
| owlrl       | OWL 2 RL rule-based reasoning                         |
| Flask       | REST API/SPARQL endpoint backend                      |
| flask-cors  | Enable cross-origin requests for UI/API               |
| requests    | Fetch and preprocess external threat feeds            |
| pandas      | Data inspection and preprocessing                     |
| D3.js       | Dynamic force-directed graph visualization (front end)|

For environment setup, refer to `environment.yml` for Conda dependencies.

## Setup and Installation

1. **Clone the repository:**
    ```bash
    git clone <repo-url>
    cd <repo-folder>
    ```

2. **Prepare the environment:**
    ```bash
    conda env create -f environment.yml
    conda activate swt
    ```

3. **Install additional dependencies as needed:**
    ```bash
    pip install -r requirements.txt
    ```

4. **(Optional) Download latest MITRE ATT&CK CTI data under `data/cti/`.**

## Usage

1. **Ingest Data:**  
    Run `ingest.py` to convert CTI/STIX JSON into RDF triples.

2. **Generate Ontology:**  
    Run `ontology.py` to define the domain OWL ontology.

3. **Run Reasoning:**  
    Execute `reasoning.py` to apply OWL RL rules and enrich the knowledge graph.

4. **Start Backend API:**  
    Launch the Flask SPARQL server:
    ```bash
    python src/app.py
    ```
    The API will serve SPARQL queries at `http://localhost:5000`.

5. **Open the Visualization:**  
    Open `ui/index.html` in your browser.  
    The D3.js front end will connect to the backend and render the interactive knowledge graph, supporting actor-centric, campaign-centric, and technique-centric exploration modes.

---

## Architecture Overview

+-------------------+      +-----------------+      +-----------------------+      +-----------------+
|  Raw CTI/STIX     |      |  Data Ingestion |      |  OWL Ontology         |      |  Reasoning      |
|  JSON Data        +-----> |  ingest.py      +----->|  cti.owl / ontology.py+----->|  OWL RL (reasoning.py)
+-------------------+      +-----------------+      +-----------------------+      +-----------------+
                                                                              |
                                                                              v
                                                                +------------------------------+
                                                                |  SPARQL API (Flask, app.py)  |
                                                                +------------------------------+
                                                                              |
                                                                              v
                                                                +------------------------------+
                                                                |  Visualization (D3.js)       |
                                                                |  index.html / js/graph.js    |
                                                                +------------------------------+

---

**Acknowledgements:**  
CTI data model based on MITRE ATT&CK (https://attack.mitre.org/).  
Developed for the TSW6223 Semantic Web Technologies course.

---
