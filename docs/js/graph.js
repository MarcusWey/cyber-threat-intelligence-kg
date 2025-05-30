const endpoint = "https://cyber-threat-intelligence-kg.onrender.com";

// --- Load Actors (with URI) ---
function loadActors() {
  fetch(endpoint + "/actors")
    .then(res => res.json())
    .then(actors => {
      const dropdown = document.getElementById('actor-dropdown');
      dropdown.innerHTML = "";
      actors.forEach(actor => {
        const opt = document.createElement('option');
        opt.value = actor.uri;
        opt.textContent = actor.name;
        opt.setAttribute("data-uri", actor.uri);
        dropdown.appendChild(opt);
      });
    })
    .catch(() => {
      const dropdown = document.getElementById('actor-dropdown');
      dropdown.innerHTML = "<option>Error loading actors</option>";
    });
}

// --- Load Campaigns (with URI) ---
function loadCampaigns() {
  fetch(endpoint + "/campaigns")
    .then(res => res.json())
    .then(campaigns => {
      const dropdown = document.getElementById('campaign-dropdown');
      dropdown.innerHTML = "";
      campaigns.forEach(camp => {
        const opt = document.createElement('option');
        opt.value = camp.uri;
        opt.textContent = camp.name;
        opt.setAttribute("data-uri", camp.uri);
        dropdown.appendChild(opt);
      });
    })
    .catch(() => {
      const dropdown = document.getElementById('campaign-dropdown');
      dropdown.innerHTML = "<option>Error loading campaigns</option>";
    });
}

// --- Draw Actor Profile ---
function drawActorProfile() {
  const dropdown = document.getElementById('actor-dropdown');
  const actorName = dropdown.options[dropdown.selectedIndex]?.text;
  if (!actorName) return;
  fetch(`${endpoint}/actor_profile?name=${encodeURIComponent(actorName)}`)
    .then(res => res.json())
    .then(data => renderGraph("ThreatActor", actorName, data))
    .catch(() => renderGraph("ThreatActor", actorName, []));
}

// --- Draw Campaign Profile ---
function drawCampaignProfile() {
  const dropdown = document.getElementById('campaign-dropdown');
  const campaignName = dropdown.options[dropdown.selectedIndex]?.text;
  if (!campaignName) return;
  fetch(`${endpoint}/campaign_profile?name=${encodeURIComponent(campaignName)}`)
    .then(res => res.json())
    .then(data => renderGraph("Campaign", campaignName, data))
    .catch(() => renderGraph("Campaign", campaignName, []));
}

// --- Load Top Techniques ---
function loadTopTechniques() {
  fetch(endpoint + "/top-techniques")
    .then(res => res.json())
    .then(data => {
      const ul = document.getElementById('top-technique-list');
      ul.innerHTML = "";
      data.forEach(row => {
        const li = document.createElement('li');
        li.innerHTML = `<a href="#" style="color:#2196f3;text-decoration:underline">${row.name}</a> <span style="color:#555;">(${row.count} uses)</span>`;
        li.querySelector('a').onclick = (e) => {
          e.preventDefault();
          showTechniqueProfile(row.name);
        };
        ul.appendChild(li);
      });
    })
    .catch(() => {
      const ul = document.getElementById('top-technique-list');
      ul.innerHTML = "<li>Error loading top techniques</li>";
    });
}

// --- Show Technique Profile ---
function showTechniqueProfile(techName) {
  const query = `PREFIX cti: <http://tswgroup41.org/cti#>
SELECT ?actor_name ?camp_name WHERE {
  { ?actor a cti:ThreatActor; cti:name ?actor_name; cti:usesTechnique ?tech. }
  UNION
  { ?camp a cti:Campaign; cti:name ?camp_name; cti:usesTechnique ?tech. }
  ?tech cti:name "${techName}".
}`;
  fetch(endpoint + "/sparql", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ query })
  })
    .then(res => res.json())
    .then(data => {
      const formatted = data.map(row => ({ tech_name: techName, actor_name: row.actor_name, camp_name: row.camp_name }));
      renderGraph("Technique", techName, formatted);
    });
}

// --- Render Graph (main D3) ---
function renderGraph(type, rootName, data) {
  const svg = d3.select("svg");
  svg.selectAll("*").remove();
  const width = +svg.node().clientWidth;
  const height = +svg.node().clientHeight;
  const tooltip = d3.select(".tooltip");
  const sidebar = document.querySelector('.sidebar');

  // Reset sidebar to instructions
  sidebar.innerHTML = `
    <strong>How to use:</strong>
    <ul style="padding-left:18px;margin-top:8px;">
      <li>Pick a <b>group</b> or <b>campaign</b> and click "Show Profile" for an interactive network view.</li>
      <li>Or, go to <b>Top Techniques</b> to see the most used attack methods.</li>
      <li>Click or hover on nodes for details.</li>
    </ul>
    <div style="margin-top:10px;color:#466;">
      This demo translates complex MITRE ATT&CK data into simple stories for students and analysts.<br>
      <span style="font-size:0.95em;">(Data: <a href="https://attack.mitre.org/" target="_blank">MITRE ATT&CK</a>)</span>
    </div>
  `;

  // build nodes & links
  const nodes = [{ id: rootName, label: rootName, group: type }];
  const links = [];
  const nodeIds = new Set([rootName]);

  data.forEach(r => {
    if (r.tech_name && !nodeIds.has(r.tech_name)) {
      nodes.push({ id: r.tech_name, label: r.tech_name, group: "Technique" });
      nodeIds.add(r.tech_name);
    }
    if (r.tech_name) links.push({ source: (type === "Technique" ? r.actor_name || r.camp_name || rootName : rootName), target: r.tech_name });
    const otherKey = type === "Technique" ? (r.actor_name || r.camp_name) : (r.tool_name || r.actor_name || r.camp_name);
    if (otherKey && !nodeIds.has(otherKey)) {
      const group = (type === "ThreatActor" ? "Tool" : (type === "Technique" ? (r.actor_name ? "ThreatActor" : "Campaign") : "Technique"));
      nodes.push({ id: otherKey, label: otherKey, group });
      nodeIds.add(otherKey);
    }
    if (r.tech_name && otherKey) links.push({ source: r.tech_name, target: otherKey });
  });

  if (nodes.length <= 1) {
    svg.append("text")
      .attr("x", width/2).attr("y", height/2)
      .attr("text-anchor","middle").attr("fill","#aaa").attr("font-size", 24)
      .text("No data for this selection");
    return;
  }

  const container = svg.append("g");
  svg.call(d3.zoom().on("zoom", (event) => {
    container.attr("transform", event.transform);
  }));

  // --- Links first
  const linkEls = container.append("g")
    .selectAll("line")
    .data(links)
    .enter().append("line")
    .attr("stroke-width", 2)
    .attr("stroke", "#888");

  // --- Nodes (append after)
  const nodeG = container.append("g")
    .selectAll("g")
    .data(nodes)
    .enter().append("g")
    .attr("cursor", "pointer");

  nodeG.append("circle")
    .attr("r", d => d.id === rootName ? 27 : 18)
    .attr("stroke", d => d.id === rootName ? "#000" : "none")
    .attr("stroke-width", d => d.id === rootName ? 3 : 0)
    .attr("fill", d => {
      if (d.group === "ThreatActor") return "#e51c23";
      if (d.group === "Campaign") return "#2e7d32";
      if (d.group === "Technique") return "#2196f3";
      if (d.group === "Tool") return "#9c27b0";
      return "#ccc";
    })
    .on("mouseover", (e, d) => {
      tooltip.html(`<strong>${d.label}</strong> (${d.group})`)
        .style("visibility", "visible");
    })
    .on("mousemove", e => {
      tooltip.style("top", (e.pageY + 10) + "px")
        .style("left", (e.pageX + 10) + "px");
    })
    .on("mouseout", () => tooltip.style("visibility", "hidden"))
    .on("click", (e, d) => {
      sidebar.innerHTML = `
        <strong>${d.label}</strong> (${d.group})<br>
        <hr>
        <span style="font-size:1em;color:#555;">(More node metadata could go here.)</span>
      `;
    });

  nodeG.append("text")
    .attr("dx", 22).attr("dy", 6)
    .attr("font-size", 15)
    .attr("font-weight", "bold")
    .attr("fill", "#222")
    .text(d => d.label.length > 20 ? d.label.slice(0, 17) + "..." : d.label);

  // --- Force Simulation ---
  const simulation = d3.forceSimulation(nodes)
    .force("link", d3.forceLink(links).id(d => d.id).distance(160))
    .force("charge", d3.forceManyBody().strength(-330))
    .force("center", d3.forceCenter(width/2, height/2))
    .force("collide", d3.forceCollide().radius(d => d.id === rootName ? 33 : 28));

  // Defensive: init positions to center for all nodes
  nodes.forEach(d => {
    d.x = width / 2;
    d.y = height / 2;
  });

  simulation.on("tick", () => {
    linkEls
      .attr("x1", d => d.source.x)
      .attr("y1", d => d.source.y)
      .attr("x2", d => d.target.x)
      .attr("y2", d => d.target.y);

    nodeG.attr("transform", d => `translate(${d.x},${d.y})`);
  });
}

// --- Tab Logic & Event Bindings ---
document.getElementById('tab-actor').addEventListener('click', () => switchTab('actor'));
document.getElementById('tab-campaign').addEventListener('click', () => switchTab('campaign'));
document.getElementById('tab-technique').addEventListener('click', () => switchTab('technique'));

function switchTab(tab) {
  ['actor','campaign','technique'].forEach(t => {
    document.getElementById('controls-'+t).style.display = t===tab? 'block':'none';
    document.getElementById('tab-'+t).classList.toggle('active', t===tab);
  });
  d3.select('svg').selectAll('*').remove();
  // Reset zoom!
  d3.select("svg").transition().duration(400)
    .call(d3.zoom().transform, d3.zoomIdentity);
}

document.getElementById('draw-actor-btn').addEventListener('click', drawActorProfile);
document.getElementById('draw-campaign-btn').addEventListener('click', drawCampaignProfile);
document.getElementById('load-top-techniques-btn').addEventListener('click', loadTopTechniques);

window.addEventListener('load', () => { loadActors(); loadCampaigns(); switchTab('actor'); });
