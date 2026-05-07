import { useState, useEffect } from "react";

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

  // ... (rest of the component logic)
}
