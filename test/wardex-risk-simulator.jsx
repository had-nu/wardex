import { useState, useEffect } from "react";

const styles = `
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;700&family=Syne:wght@400;600;800&display=swap');

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: #0a0c0f;
    color: #e2e8f0;
    font-family: 'JetBrains Mono', monospace;
    min-height: 100vh;
  }

  :root {
    --red: #ff3b3b;
    --amber: #f59e0b;
    --green: #10b981;
    --cyan: #06b6d4;
    --dim: #3d4a5c;
    --surface: #111827;
    --surface2: #1a2332;
    --border: #1e293b;
    --text-dim: #64748b;
  }

  .app {
    max-width: 900px;
    margin: 0 auto;
    padding: 2rem 1.5rem;
  }

  .header {
    margin-bottom: 2.5rem;
    border-bottom: 1px solid var(--border);
    padding-bottom: 1.5rem;
  }

  .header-label {
    font-size: 0.65rem;
    letter-spacing: 0.2em;
    color: var(--text-dim);
    text-transform: uppercase;
    margin-bottom: 0.4rem;
  }

  .header h1 {
    font-family: 'Syne', sans-serif;
    font-size: 1.6rem;
    font-weight: 800;
    color: #f1f5f9;
    letter-spacing: -0.02em;
  }

  .header h1 span {
    color: var(--cyan);
  }

  .header-sub {
    font-size: 0.7rem;
    color: var(--text-dim);
    margin-top: 0.4rem;
    letter-spacing: 0.05em;
  }

  .grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
    margin-bottom: 1rem;
  }

  @media (max-width: 640px) {
    .grid { grid-template-columns: 1fr; }
  }

  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.2rem;
  }

  .card-title {
    font-size: 0.6rem;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    color: var(--text-dim);
    margin-bottom: 1rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .card-title::after {
    content: '';
    flex: 1;
    height: 1px;
    background: var(--border);
  }

  .field {
    margin-bottom: 1rem;
  }

  .field:last-child { margin-bottom: 0; }

  .field label {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    font-size: 0.7rem;
    color: #94a3b8;
    margin-bottom: 0.4rem;
    letter-spacing: 0.03em;
  }

  .field label span {
    font-size: 0.75rem;
    color: var(--cyan);
    font-weight: 500;
  }

  input[type="range"] {
    -webkit-appearance: none;
    width: 100%;
    height: 3px;
    background: var(--dim);
    border-radius: 2px;
    outline: none;
    cursor: pointer;
  }

  input[type="range"]::-webkit-slider-thumb {
    -webkit-appearance: none;
    width: 14px;
    height: 14px;
    border-radius: 50%;
    background: var(--cyan);
    cursor: pointer;
    border: 2px solid #0a0c0f;
    box-shadow: 0 0 8px rgba(6,182,212,0.4);
    transition: box-shadow 0.15s;
  }

  input[type="range"]:hover::-webkit-slider-thumb {
    box-shadow: 0 0 14px rgba(6,182,212,0.7);
  }

  .toggle-group {
    display: flex;
    gap: 0.3rem;
  }

  .toggle-btn {
    flex: 1;
    padding: 0.35rem 0.5rem;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.65rem;
    border: 1px solid var(--border);
    border-radius: 4px;
    background: transparent;
    color: var(--text-dim);
    cursor: pointer;
    letter-spacing: 0.05em;
    transition: all 0.15s;
    text-align: center;
  }

  .toggle-btn.active {
    background: rgba(6,182,212,0.12);
    border-color: var(--cyan);
    color: var(--cyan);
  }

  .toggle-btn:hover:not(.active) {
    border-color: var(--dim);
    color: #94a3b8;
  }

  .compensating-controls {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .ctrl-item {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 5px;
    padding: 0.4rem 0.6rem;
  }

  .ctrl-checkbox {
    width: 14px;
    height: 14px;
    accent-color: var(--cyan);
    cursor: pointer;
    flex-shrink: 0;
  }

  .ctrl-name {
    font-size: 0.65rem;
    color: #94a3b8;
    flex: 1;
    letter-spacing: 0.03em;
  }

  .ctrl-effect {
    font-size: 0.65rem;
    color: var(--cyan);
    font-weight: 500;
    min-width: 2rem;
    text-align: right;
  }

  .ctrl-effect.inactive {
    color: var(--dim);
  }

  /* Result Panel */
  .result-panel {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.5rem;
    margin-bottom: 1rem;
    position: relative;
    overflow: hidden;
  }

  .result-panel::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: var(--decision-color, var(--dim));
    transition: background 0.3s;
  }

  .result-top {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    margin-bottom: 1.5rem;
  }

  .decision-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    padding: 0.4rem 0.9rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 700;
    letter-spacing: 0.12em;
    border: 1px solid currentColor;
  }

  .decision-block {
    color: var(--red);
    background: rgba(255,59,59,0.08);
  }

  .decision-warn {
    color: var(--amber);
    background: rgba(245,158,11,0.08);
  }

  .decision-allow {
    color: var(--green);
    background: rgba(16,185,129,0.08);
  }

  .risk-score-display {
    text-align: right;
  }

  .risk-score-label {
    font-size: 0.6rem;
    color: var(--text-dim);
    letter-spacing: 0.15em;
    text-transform: uppercase;
    margin-bottom: 0.2rem;
  }

  .risk-score-value {
    font-family: 'Syne', sans-serif;
    font-size: 2.8rem;
    font-weight: 800;
    line-height: 1;
    transition: color 0.3s;
  }

  .risk-score-appetite {
    font-size: 0.6rem;
    color: var(--text-dim);
    margin-top: 0.2rem;
  }

  /* Score bar */
  .score-bar-container {
    margin-bottom: 1.5rem;
  }

  .score-bar-track {
    height: 6px;
    background: var(--dim);
    border-radius: 3px;
    position: relative;
    overflow: hidden;
  }

  .score-bar-fill {
    height: 100%;
    border-radius: 3px;
    transition: width 0.3s ease, background 0.3s;
  }

  .score-bar-appetite {
    position: absolute;
    top: -4px;
    width: 2px;
    height: 14px;
    background: #ffffff44;
    border-radius: 1px;
  }

  .score-bar-labels {
    display: flex;
    justify-content: space-between;
    margin-top: 0.4rem;
    font-size: 0.6rem;
    color: var(--text-dim);
  }

  /* Breakdown */
  .breakdown {
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
  }

  .breakdown-row {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    font-size: 0.68rem;
  }

  .breakdown-key {
    color: var(--text-dim);
    min-width: 160px;
    letter-spacing: 0.03em;
  }

  .breakdown-op {
    color: var(--dim);
    font-size: 0.65rem;
  }

  .breakdown-val {
    color: #cbd5e1;
    font-weight: 500;
  }

  .breakdown-val.highlight {
    color: var(--cyan);
  }

  .breakdown-separator {
    height: 1px;
    background: var(--border);
    margin: 0.3rem 0;
  }

  .breakdown-final {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    font-size: 0.75rem;
    font-weight: 600;
  }

  .breakdown-final .breakdown-key {
    color: #94a3b8;
    font-weight: 600;
  }

  .clamp-note {
    font-size: 0.6rem;
    color: var(--amber);
    margin-top: 0.6rem;
    display: flex;
    align-items: center;
    gap: 0.3rem;
    letter-spacing: 0.03em;
  }

  /* Appetite control */
  .appetite-row {
    display: flex;
    align-items: center;
    gap: 1rem;
    padding: 0.8rem 1.2rem;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    margin-bottom: 1rem;
  }

  .appetite-label {
    font-size: 0.65rem;
    color: var(--text-dim);
    letter-spacing: 0.1em;
    text-transform: uppercase;
    white-space: nowrap;
  }

  .appetite-val {
    font-size: 1rem;
    color: #f1f5f9;
    font-weight: 700;
    min-width: 2rem;
    text-align: right;
    white-space: nowrap;
  }

  .formula-line {
    font-size: 0.65rem;
    color: var(--text-dim);
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.8rem 1rem;
    letter-spacing: 0.03em;
    line-height: 2;
    font-family: 'JetBrains Mono', monospace;
  }

  .formula-line .var { color: var(--cyan); }
  .formula-line .op  { color: var(--dim); }
  .formula-line .val { color: #f1f5f9; }
`;

const COMPENSATING_CONTROLS = [
  { id: "waf",          name: "WAF",                    effectiveness: 0.35 },
  { id: "netseg",       name: "Network Segmentation",   effectiveness: 0.25 },
  { id: "runtime",      name: "Runtime Protection",     effectiveness: 0.20 },
  { id: "ids",          name: "IDS/IPS",                effectiveness: 0.15 },
  { id: "mfa",          name: "MFA enforced",           effectiveness: 0.10 },
];

function clamp(v, min, max) { return Math.min(Math.max(v, min), max); }

function calcRisk(params) {
  const {
    cvssBase, epssScore, assetCriticality,
    exposure, requiresAuth, activeControls, riskAppetite
  } = params;

  const epssF = epssScore;
  const adjustedScore = cvssBase * epssF;

  const exposureWeights = { internet: 1.0, internal: 0.6, airgapped: 0.3 };
  const internetW = exposureWeights[exposure];
  const authR = requiresAuth ? 0.2 : 0.0;
  const exposureFactor = internetW * (1 - authR);

  const rawCompensating = activeControls.reduce((acc, id) => {
    const ctrl = COMPENSATING_CONTROLS.find(c => c.id === id);
    return acc + (ctrl ? ctrl.effectiveness : 0);
  }, 0);
  const compensatingEffect = clamp(rawCompensating, 0, 0.8);
  const wasClamped = rawCompensating > 0.8;

  const compensatedScore = adjustedScore * (1 - compensatingEffect);
  const releaseRisk = compensatedScore * assetCriticality * exposureFactor;

  return {
    epssF,
    adjustedScore,
    internetW,
    authR,
    exposureFactor,
    rawCompensating,
    compensatingEffect,
    wasClamped,
    compensatedScore,
    releaseRisk: Math.min(releaseRisk, 10),
    decision: releaseRisk > riskAppetite ? "block"
            : releaseRisk > riskAppetite * 0.8 ? "warn"
            : "allow"
  };
}

export default function WardexRiskSimulator() {
  const [cvssBase, setCvssBase]             = useState(9.1);
  const [epssScore, setEpssScore]           = useState(0.84);
  const [assetCriticality, setAsset]        = useState(0.9);
  const [exposure, setExposure]             = useState("internet");
  const [requiresAuth, setRequiresAuth]     = useState(true);
  const [riskAppetite, setRiskAppetite]     = useState(6.0);
  const [activeControls, setActiveControls] = useState(["waf", "netseg"]);

  const toggleControl = (id) => {
    setActiveControls(prev =>
      prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]
    );
  };

  const result = calcRisk({
    cvssBase, epssScore, assetCriticality,
    exposure, requiresAuth, activeControls, riskAppetite
  });

  const riskColor = result.decision === "block" ? "var(--red)"
                  : result.decision === "warn"  ? "var(--amber)"
                  : "var(--green)";

  const pct = (result.releaseRisk / 10) * 100;
  const appetitePct = (riskAppetite / 10) * 100;

  return (
    <>
      <style>{styles}</style>
      <div className="app">
        <div className="header">
          <div className="header-label">wardex · release gate</div>
          <h1>Risk <span>Formula</span> Simulator</h1>
          <div className="header-sub">release_risk = cvss × epss × criticality × exposure × (1 − compensating)</div>
        </div>

        {/* Result Panel */}
        <div className="result-panel" style={{"--decision-color": riskColor}}>
          <div className="result-top">
            <div>
              <div className={`decision-badge decision-${result.decision}`}>
                {result.decision === "block" ? "⛔ BLOCK"
                : result.decision === "warn"  ? "⚠ WARN"
                : "✓ ALLOW"}
              </div>
            </div>
            <div className="risk-score-display">
              <div className="risk-score-label">release_risk</div>
              <div className="risk-score-value" style={{color: riskColor}}>
                {result.releaseRisk.toFixed(2)}
              </div>
              <div className="risk-score-appetite">appetite: {riskAppetite.toFixed(1)}</div>
            </div>
          </div>

          <div className="score-bar-container">
            <div className="score-bar-track">
              <div className="score-bar-fill"
                style={{
                  width: `${pct}%`,
                  background: riskColor,
                  opacity: 0.85
                }}
              />
              <div className="score-bar-appetite" style={{left: `${appetitePct}%`}} />
            </div>
            <div className="score-bar-labels">
              <span>0.0</span>
              <span style={{color: "#ffffff55", fontSize: "0.55rem"}}>▲ appetite {riskAppetite.toFixed(1)}</span>
              <span>10.0</span>
            </div>
          </div>

          <div className="breakdown">
            <div className="breakdown-row">
              <span className="breakdown-key">cvss_base</span>
              <span className="breakdown-op">=</span>
              <span className="breakdown-val highlight">{cvssBase.toFixed(1)}</span>
            </div>
            <div className="breakdown-row">
              <span className="breakdown-key">epss_factor</span>
              <span className="breakdown-op">=</span>
              <span className="breakdown-val highlight">{result.epssF.toFixed(2)}</span>
            </div>
            <div className="breakdown-row">
              <span className="breakdown-key">adjusted_score</span>
              <span className="breakdown-op">= {cvssBase.toFixed(1)} × {result.epssF.toFixed(2)} =</span>
              <span className="breakdown-val">{result.adjustedScore.toFixed(3)}</span>
            </div>
            <div className="breakdown-separator"/>
            <div className="breakdown-row">
              <span className="breakdown-key">internet_facing_weight</span>
              <span className="breakdown-op">=</span>
              <span className="breakdown-val highlight">{result.internetW.toFixed(1)}</span>
            </div>
            <div className="breakdown-row">
              <span className="breakdown-key">auth_reduction</span>
              <span className="breakdown-op">=</span>
              <span className="breakdown-val highlight">{result.authR.toFixed(1)}</span>
            </div>
            <div className="breakdown-row">
              <span className="breakdown-key">exposure_factor</span>
              <span className="breakdown-op">= {result.internetW.toFixed(1)} × (1 − {result.authR.toFixed(1)}) =</span>
              <span className="breakdown-val">{result.exposureFactor.toFixed(3)}</span>
            </div>
            <div className="breakdown-separator"/>
            <div className="breakdown-row">
              <span className="breakdown-key">compensating_effect</span>
              <span className="breakdown-op">= clamp({result.rawCompensating.toFixed(2)}, 0, 0.8) =</span>
              <span className="breakdown-val highlight">{result.compensatingEffect.toFixed(2)}</span>
            </div>
            <div className="breakdown-row">
              <span className="breakdown-key">compensated_score</span>
              <span className="breakdown-op">= {result.adjustedScore.toFixed(3)} × (1 − {result.compensatingEffect.toFixed(2)}) =</span>
              <span className="breakdown-val">{result.compensatedScore.toFixed(3)}</span>
            </div>
            <div className="breakdown-separator"/>
            <div className="breakdown-final">
              <span className="breakdown-key">release_risk</span>
              <span className="breakdown-op">= {result.compensatedScore.toFixed(3)} × {assetCriticality.toFixed(2)} × {result.exposureFactor.toFixed(3)} =</span>
              <span className="breakdown-val" style={{color: riskColor, fontSize: "0.9rem"}}>{result.releaseRisk.toFixed(3)}</span>
            </div>
          </div>

          {result.wasClamped && (
            <div className="clamp-note">
              ⚑ compensating_effectiveness clamped em 0.80 (raw: {result.rawCompensating.toFixed(2)}) — nenhuma combinação elimina o risco por completo
            </div>
          )}
        </div>

        {/* Risk appetite */}
        <div className="appetite-row">
          <span className="appetite-label">risk_appetite</span>
          <input type="range" min="1" max="10" step="0.1"
            value={riskAppetite}
            onChange={e => setRiskAppetite(parseFloat(e.target.value))}
            style={{flex: 1}}
          />
          <span className="appetite-val">{riskAppetite.toFixed(1)}</span>
        </div>

        <div className="grid">
          {/* Vulnerability */}
          <div className="card">
            <div className="card-title">Vulnerability</div>

            <div className="field">
              <label>cvss_base <span>{cvssBase.toFixed(1)}</span></label>
              <input type="range" min="0" max="10" step="0.1"
                value={cvssBase}
                onChange={e => setCvssBase(parseFloat(e.target.value))}
              />
            </div>

            <div className="field">
              <label>epss_factor <span>{epssScore.toFixed(2)}</span></label>
              <input type="range" min="0.01" max="1" step="0.01"
                value={epssScore}
                onChange={e => setEpssScore(parseFloat(e.target.value))}
              />
            </div>
          </div>

          {/* Asset Context */}
          <div className="card">
            <div className="card-title">Asset Context</div>

            <div className="field">
              <label>asset_criticality <span>{assetCriticality.toFixed(2)}</span></label>
              <input type="range" min="0" max="1" step="0.01"
                value={assetCriticality}
                onChange={e => setAsset(parseFloat(e.target.value))}
              />
            </div>

            <div className="field">
              <label>exposure</label>
              <div className="toggle-group">
                {["internet", "internal", "airgapped"].map(e => (
                  <button key={e}
                    className={`toggle-btn ${exposure === e ? "active" : ""}`}
                    onClick={() => setExposure(e)}
                  >
                    {e === "internet" ? "internet" : e === "internal" ? "internal" : "air-gap"}
                  </button>
                ))}
              </div>
            </div>

            <div className="field">
              <label>requires_auth</label>
              <div className="toggle-group">
                <button className={`toggle-btn ${requiresAuth ? "active" : ""}`}
                  onClick={() => setRequiresAuth(true)}>yes</button>
                <button className={`toggle-btn ${!requiresAuth ? "active" : ""}`}
                  onClick={() => setRequiresAuth(false)}>no</button>
              </div>
            </div>
          </div>
        </div>

        {/* Compensating Controls */}
        <div className="card" style={{marginBottom: "1rem"}}>
          <div className="card-title">Compensating Controls</div>
          <div className="compensating-controls">
            {COMPENSATING_CONTROLS.map(ctrl => (
              <div key={ctrl.id} className="ctrl-item">
                <input type="checkbox"
                  className="ctrl-checkbox"
                  checked={activeControls.includes(ctrl.id)}
                  onChange={() => toggleControl(ctrl.id)}
                />
                <span className="ctrl-name">{ctrl.name}</span>
                <span className={`ctrl-effect ${activeControls.includes(ctrl.id) ? "" : "inactive"}`}>
                  −{(ctrl.effectiveness * 100).toFixed(0)}%
                </span>
              </div>
            ))}
          </div>
          {activeControls.length > 0 && (
            <div style={{marginTop: "0.8rem", fontSize: "0.65rem", color: "var(--text-dim)"}}>
              raw: {result.rawCompensating.toFixed(2)} → clamped: {result.compensatingEffect.toFixed(2)} / 0.80 max
            </div>
          )}
        </div>

        {/* Formula reference */}
        <div className="formula-line">
          <span className="var">adjusted_score</span>
          <span className="op"> = </span>
          <span className="var">cvss_base</span>
          <span className="op"> × </span>
          <span className="var">epss_factor</span>
          <br/>
          <span className="var">exposure_factor</span>
          <span className="op"> = </span>
          <span className="var">inet_weight</span>
          <span className="op"> × (1 − </span>
          <span className="var">auth_reduction</span>
          <span className="op">)</span>
          <br/>
          <span className="var">compensated_score</span>
          <span className="op"> = </span>
          <span className="var">adjusted_score</span>
          <span className="op"> × (1 − </span>
          <span className="var">clamp(compensating, 0, 0.8)</span>
          <span className="op">)</span>
          <br/>
          <span className="var">release_risk</span>
          <span className="op"> = </span>
          <span className="var">compensated_score</span>
          <span className="op"> × </span>
          <span className="var">asset_criticality</span>
          <span className="op"> × </span>
          <span className="var">exposure_factor</span>
        </div>
      </div>
    </>
  );
}
