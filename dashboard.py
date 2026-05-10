"""
dashboard.py
------------
Flask Web Dashboard for AI-SecureScan.
Run: python dashboard.py
Open: http://localhost:5000
"""

import os
import json
import threading
from pathlib import Path
from datetime import datetime, timezone
from flask import Flask, render_template_string, request, jsonify, Response
import queue

app = Flask(__name__)

# Global scan state
scan_queue = queue.Queue()
scan_status = {
    "running": False,
    "stage": "",
    "progress": 0,
    "logs": [],
    "result": None,
    "error": None,
}

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AI-SecureScan Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #090e14;
    --panel: #0d1520;
    --border: #1a2e45;
    --accent: #00d4ff;
    --accent2: #ff3c6e;
    --accent3: #39ff14;
    --warn: #ffaa00;
    --text: #c8e0f0;
    --muted: #4a6b85;
    --critical: #ff3c6e;
    --high: #ff7700;
    --medium: #ffaa00;
    --low: #39ff14;
    --info: #00d4ff;
  }

  * { margin: 0; padding: 0; box-sizing: border-box; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'Rajdhani', sans-serif;
    font-size: 16px;
    min-height: 100vh;
    overflow-x: hidden;
  }

  /* Grid background */
  body::before {
    content: '';
    position: fixed;
    inset: 0;
    background-image:
      linear-gradient(rgba(0,212,255,0.03) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0,212,255,0.03) 1px, transparent 1px);
    background-size: 40px 40px;
    pointer-events: none;
    z-index: 0;
  }

  /* Scanline effect */
  body::after {
    content: '';
    position: fixed;
    inset: 0;
    background: repeating-linear-gradient(
      0deg,
      transparent,
      transparent 2px,
      rgba(0,0,0,0.1) 2px,
      rgba(0,0,0,0.1) 4px
    );
    pointer-events: none;
    z-index: 0;
  }

  .wrapper { position: relative; z-index: 1; }

  /* Header */
  header {
    border-bottom: 1px solid var(--border);
    padding: 20px 40px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    background: rgba(13,21,32,0.9);
    backdrop-filter: blur(10px);
    position: sticky;
    top: 0;
    z-index: 100;
  }

  .logo {
    display: flex;
    align-items: center;
    gap: 14px;
  }

  .logo-icon {
    width: 42px; height: 42px;
    border: 2px solid var(--accent);
    border-radius: 8px;
    display: flex; align-items: center; justify-content: center;
    font-size: 20px;
    box-shadow: 0 0 20px rgba(0,212,255,0.3);
    animation: pulse-border 3s ease-in-out infinite;
  }

  @keyframes pulse-border {
    0%, 100% { box-shadow: 0 0 20px rgba(0,212,255,0.3); }
    50% { box-shadow: 0 0 35px rgba(0,212,255,0.6); }
  }

  .logo-text h1 {
    font-size: 22px;
    font-weight: 700;
    letter-spacing: 3px;
    color: var(--accent);
    text-shadow: 0 0 20px rgba(0,212,255,0.5);
  }

  .logo-text p {
    font-family: 'Share Tech Mono', monospace;
    font-size: 11px;
    color: var(--muted);
    letter-spacing: 2px;
  }

  .status-badge {
    font-family: 'Share Tech Mono', monospace;
    font-size: 12px;
    padding: 6px 14px;
    border-radius: 4px;
    border: 1px solid var(--muted);
    color: var(--muted);
    letter-spacing: 2px;
    transition: all 0.3s;
  }

  .status-badge.running {
    border-color: var(--accent3);
    color: var(--accent3);
    box-shadow: 0 0 15px rgba(57,255,20,0.3);
    animation: blink 1s step-end infinite;
  }

  @keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }

  /* Main layout */
  .main { display: grid; grid-template-columns: 380px 1fr; gap: 0; min-height: calc(100vh - 83px); }

  /* Sidebar */
  .sidebar {
    border-right: 1px solid var(--border);
    padding: 30px 24px;
    background: rgba(13,21,32,0.6);
    display: flex;
    flex-direction: column;
    gap: 24px;
  }

  .section-label {
    font-family: 'Share Tech Mono', monospace;
    font-size: 11px;
    letter-spacing: 3px;
    color: var(--muted);
    margin-bottom: 12px;
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .section-label::after {
    content: '';
    flex: 1;
    height: 1px;
    background: var(--border);
  }

  /* Form */
  .form-group { margin-bottom: 16px; }

  label {
    display: block;
    font-size: 13px;
    font-weight: 600;
    letter-spacing: 1px;
    color: var(--accent);
    margin-bottom: 7px;
    font-family: 'Share Tech Mono', monospace;
  }

  input, select {
    width: 100%;
    background: rgba(0,212,255,0.04);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 10px 14px;
    color: var(--text);
    font-family: 'Share Tech Mono', monospace;
    font-size: 14px;
    outline: none;
    transition: all 0.2s;
  }

  input:focus, select:focus {
    border-color: var(--accent);
    background: rgba(0,212,255,0.07);
    box-shadow: 0 0 0 2px rgba(0,212,255,0.1);
  }

  input::placeholder { color: var(--muted); }

  .checkbox-row {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px 14px;
    background: rgba(0,212,255,0.04);
    border: 1px solid var(--border);
    border-radius: 6px;
    cursor: pointer;
    transition: all 0.2s;
  }

  .checkbox-row:hover { border-color: var(--accent); background: rgba(0,212,255,0.07); }

  .checkbox-row input[type=checkbox] {
    width: auto;
    accent-color: var(--accent);
  }

  .checkbox-row span {
    font-family: 'Share Tech Mono', monospace;
    font-size: 13px;
    color: var(--text);
  }

  .btn-scan {
    width: 100%;
    padding: 14px;
    background: transparent;
    border: 2px solid var(--accent);
    border-radius: 6px;
    color: var(--accent);
    font-family: 'Rajdhani', sans-serif;
    font-size: 16px;
    font-weight: 700;
    letter-spacing: 4px;
    cursor: pointer;
    transition: all 0.3s;
    text-transform: uppercase;
    position: relative;
    overflow: hidden;
  }

  .btn-scan::before {
    content: '';
    position: absolute;
    inset: 0;
    background: var(--accent);
    transform: translateX(-100%);
    transition: transform 0.3s;
    z-index: -1;
  }

  .btn-scan:hover {
    color: var(--bg);
    box-shadow: 0 0 30px rgba(0,212,255,0.4);
  }

  .btn-scan:hover::before { transform: translateX(0); }
  .btn-scan:disabled { opacity: 0.4; cursor: not-allowed; }
  .btn-scan:disabled::before { display: none; }

  .btn-stop {
    width: 100%;
    padding: 10px;
    background: transparent;
    border: 1px solid var(--accent2);
    border-radius: 6px;
    color: var(--accent2);
    font-family: 'Share Tech Mono', monospace;
    font-size: 13px;
    cursor: pointer;
    transition: all 0.2s;
    display: none;
  }

  .btn-stop:hover { background: rgba(255,60,110,0.1); }

  /* Pipeline stages */
  .pipeline { display: flex; flex-direction: column; gap: 8px; }

  .stage-item {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 10px 14px;
    border: 1px solid var(--border);
    border-radius: 6px;
    background: rgba(0,0,0,0.2);
    transition: all 0.3s;
    font-size: 14px;
  }

  .stage-item.active {
    border-color: var(--accent);
    background: rgba(0,212,255,0.07);
    box-shadow: 0 0 15px rgba(0,212,255,0.15);
  }

  .stage-item.done {
    border-color: var(--accent3);
    color: var(--accent3);
  }

  .stage-item.error { border-color: var(--accent2); color: var(--accent2); }

  .stage-dot {
    width: 8px; height: 8px;
    border-radius: 50%;
    background: var(--muted);
    flex-shrink: 0;
    transition: all 0.3s;
  }

  .stage-item.active .stage-dot {
    background: var(--accent);
    box-shadow: 0 0 10px var(--accent);
    animation: blink 0.8s step-end infinite;
  }

  .stage-item.done .stage-dot { background: var(--accent3); }
  .stage-item.error .stage-dot { background: var(--accent2); }

  /* Content area */
  .content { padding: 30px; overflow-y: auto; }

  /* Progress bar */
  .progress-section { margin-bottom: 28px; }

  .progress-bar-wrap {
    background: rgba(255,255,255,0.05);
    border: 1px solid var(--border);
    border-radius: 4px;
    height: 8px;
    overflow: hidden;
    margin-top: 10px;
  }

  .progress-bar-fill {
    height: 100%;
    background: linear-gradient(90deg, var(--accent), var(--accent3));
    border-radius: 4px;
    transition: width 0.5s ease;
    box-shadow: 0 0 10px var(--accent);
    width: 0%;
  }

  /* Cards grid */
  .cards-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 16px;
    margin-bottom: 28px;
  }

  .metric-card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
    position: relative;
    overflow: hidden;
    transition: all 0.3s;
  }

  .metric-card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: var(--accent);
  }

  .metric-card:hover { border-color: var(--accent); transform: translateY(-2px); }

  .metric-card .label {
    font-family: 'Share Tech Mono', monospace;
    font-size: 11px;
    color: var(--muted);
    letter-spacing: 2px;
    margin-bottom: 10px;
  }

  .metric-card .value {
    font-size: 32px;
    font-weight: 700;
    color: var(--accent);
    line-height: 1;
    text-shadow: 0 0 20px rgba(0,212,255,0.4);
  }

  .metric-card .sub { font-size: 13px; color: var(--muted); margin-top: 6px; }

  .metric-card.critical-card::before { background: var(--critical); }
  .metric-card.critical-card .value { color: var(--critical); text-shadow: 0 0 20px rgba(255,60,110,0.4); }
  .metric-card.warn-card::before { background: var(--warn); }
  .metric-card.warn-card .value { color: var(--warn); }
  .metric-card.good-card::before { background: var(--accent3); }
  .metric-card.good-card .value { color: var(--accent3); }

  /* Tabs */
  .tabs { display: flex; gap: 4px; margin-bottom: 20px; border-bottom: 1px solid var(--border); }

  .tab-btn {
    padding: 10px 20px;
    background: transparent;
    border: none;
    border-bottom: 2px solid transparent;
    color: var(--muted);
    font-family: 'Rajdhani', sans-serif;
    font-size: 15px;
    font-weight: 600;
    letter-spacing: 1px;
    cursor: pointer;
    transition: all 0.2s;
    margin-bottom: -1px;
  }

  .tab-btn:hover { color: var(--text); }
  .tab-btn.active { color: var(--accent); border-bottom-color: var(--accent); }

  .tab-content { display: none; }
  .tab-content.active { display: block; }

  /* Log terminal */
  .terminal {
    background: #050a0f;
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 13px;
    height: 320px;
    overflow-y: auto;
    line-height: 1.7;
  }

  .terminal::-webkit-scrollbar { width: 6px; }
  .terminal::-webkit-scrollbar-track { background: transparent; }
  .terminal::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }

  .log-line { margin-bottom: 3px; }
  .log-line .ts { color: var(--muted); margin-right: 10px; }
  .log-line.INFO .msg { color: var(--text); }
  .log-line.WARNING .msg { color: var(--warn); }
  .log-line.ERROR .msg { color: var(--critical); }
  .log-line.SUCCESS .msg { color: var(--accent3); }
  .log-line.STAGE .msg { color: var(--accent); font-weight: bold; }

  /* Findings table */
  .findings-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 14px;
  }

  .findings-table th {
    text-align: left;
    padding: 10px 14px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 11px;
    letter-spacing: 2px;
    color: var(--muted);
    border-bottom: 1px solid var(--border);
  }

  .findings-table td {
    padding: 10px 14px;
    border-bottom: 1px solid rgba(26,46,69,0.5);
    vertical-align: top;
  }

  .findings-table tr:hover td { background: rgba(0,212,255,0.03); }

  .severity-badge {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 3px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 11px;
    font-weight: bold;
    letter-spacing: 1px;
  }

  .sev-CRITICAL { background: rgba(255,60,110,0.15); color: var(--critical); border: 1px solid rgba(255,60,110,0.3); }
  .sev-HIGH { background: rgba(255,119,0,0.15); color: var(--high); border: 1px solid rgba(255,119,0,0.3); }
  .sev-MEDIUM { background: rgba(255,170,0,0.15); color: var(--warn); border: 1px solid rgba(255,170,0,0.3); }
  .sev-LOW { background: rgba(57,255,20,0.15); color: var(--low); border: 1px solid rgba(57,255,20,0.3); }
  .sev-INFO { background: rgba(0,212,255,0.15); color: var(--info); border: 1px solid rgba(0,212,255,0.3); }

  /* Score gauge */
  .score-display {
    display: flex;
    align-items: center;
    gap: 40px;
    padding: 28px;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    margin-bottom: 24px;
  }

  .score-circle {
    width: 130px; height: 130px;
    border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    flex-direction: column;
    position: relative;
    flex-shrink: 0;
  }

  .score-number {
    font-size: 42px;
    font-weight: 700;
    line-height: 1;
  }

  .score-label {
    font-family: 'Share Tech Mono', monospace;
    font-size: 11px;
    color: var(--muted);
    letter-spacing: 2px;
    margin-top: 4px;
  }

  .score-details { flex: 1; }

  .score-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 10px 0;
    border-bottom: 1px solid var(--border);
    font-size: 15px;
  }

  .score-row:last-child { border-bottom: none; }
  .score-row .sname { color: var(--muted); font-family: 'Share Tech Mono', monospace; font-size: 13px; }
  .score-row .sval { font-weight: 700; font-size: 18px; }

  /* Paths list */
  .paths-list {
    background: #050a0f;
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 13px;
    max-height: 400px;
    overflow-y: auto;
  }

  .path-item {
    display: flex;
    align-items: center;
    gap: 14px;
    padding: 6px 0;
    border-bottom: 1px solid rgba(26,46,69,0.4);
  }

  .path-status { font-weight: bold; min-width: 36px; }
  .s200 { color: var(--accent3); }
  .s301, .s302 { color: var(--warn); }
  .s403 { color: var(--high); }
  .s500 { color: var(--critical); }
  .path-url { color: var(--text); flex: 1; }
  .path-size { color: var(--muted); font-size: 11px; }

  /* Welcome screen */
  .welcome {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    min-height: 400px;
    text-align: center;
    gap: 20px;
  }

  .welcome-icon {
    font-size: 64px;
    opacity: 0.15;
    animation: float 4s ease-in-out infinite;
  }

  @keyframes float {
    0%, 100% { transform: translateY(0); }
    50% { transform: translateY(-12px); }
  }

  .welcome h2 {
    font-size: 28px;
    font-weight: 700;
    letter-spacing: 4px;
    color: var(--accent);
    opacity: 0.6;
  }

  .welcome p {
    color: var(--muted);
    font-family: 'Share Tech Mono', monospace;
    font-size: 13px;
    letter-spacing: 2px;
  }

  /* Alert box */
  .alert {
    padding: 14px 18px;
    border-radius: 6px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 13px;
    margin-bottom: 20px;
    display: none;
  }

  .alert.error { background: rgba(255,60,110,0.1); border: 1px solid rgba(255,60,110,0.3); color: var(--critical); display: block; }
  .alert.success { background: rgba(57,255,20,0.1); border: 1px solid rgba(57,255,20,0.3); color: var(--accent3); display: block; }

  /* Responsive */
  @media (max-width: 900px) {
    .main { grid-template-columns: 1fr; }
    .sidebar { border-right: none; border-bottom: 1px solid var(--border); }
  }
</style>
</head>
<body>
<div class="wrapper">

<!-- Header -->
<header>
  <div class="logo">
    <div class="logo-icon">🛡️</div>
    <div class="logo-text">
      <h1>AI-SECURESCAN</h1>
      <p>AGENTIC VULNERABILITY ASSESSMENT ENGINE</p>
    </div>
  </div>
  <div class="status-badge" id="statusBadge">STANDBY</div>
</header>

<!-- Main -->
<div class="main">

  <!-- Sidebar -->
  <aside class="sidebar">
    <div>
      <div class="section-label">TARGET CONFIG</div>
      <div class="form-group">
        <label>TARGET IP / HOST</label>
        <input type="text" id="target" placeholder="192.168.1.1" />
      </div>
      <div class="form-group">
        <label>WEB PORT</label>
        <input type="number" id="port" value="80" placeholder="80" />
      </div>
      <div class="form-group">
        <label>DOMAIN (DNS ENUM)</label>
        <input type="text" id="domain" placeholder="example.com (optional)" />
      </div>
    </div>

    <div>
      <div class="section-label">OPTIONS</div>
      <label class="checkbox-row">
        <input type="checkbox" id="safeMode" checked />
        <span>SAFE MODE (no real execution)</span>
      </label>
    </div>

    <div>
      <div id="alertBox" class="alert"></div>
      <button class="btn-scan" id="btnScan" onclick="startScan()">▶ INITIATE SCAN</button>
      <br><br>
      <button class="btn-stop" id="btnStop" onclick="stopScan()">■ STOP</button>
    </div>

    <div>
      <div class="section-label">PIPELINE STAGES</div>
      <div class="pipeline" id="pipeline">
        <div class="stage-item" id="stage-1"><div class="stage-dot"></div>[1] Strategy Agent</div>
        <div class="stage-item" id="stage-2"><div class="stage-dot"></div>[2] Execution Agent</div>
        <div class="stage-item" id="stage-3"><div class="stage-dot"></div>[3] Review Agent</div>
        <div class="stage-item" id="stage-4"><div class="stage-dot"></div>[4] Feroxbuster Agent</div>
        <div class="stage-item" id="stage-5"><div class="stage-dot"></div>[5] Enumeration Agent</div>
        <div class="stage-item" id="stage-6"><div class="stage-dot"></div>[6] Nikto Agent</div>
        <div class="stage-item" id="stage-7"><div class="stage-dot"></div>[7] Mitigation Agent</div>
        <div class="stage-item" id="stage-8"><div class="stage-dot"></div>[8] Reporting Agent</div>
      </div>
    </div>
  </aside>

  <!-- Content -->
  <main class="content">

    <!-- Welcome screen -->
    <div class="welcome" id="welcomeScreen">
      <div class="welcome-icon">🔍</div>
      <h2>READY TO SCAN</h2>
      <p>ENTER TARGET · CONFIGURE OPTIONS · INITIATE SCAN</p>
    </div>

    <!-- Results (hidden until scan) -->
    <div id="resultsArea" style="display:none;">

      <!-- Progress -->
      <div class="progress-section">
        <div class="section-label">SCAN PROGRESS</div>
        <div style="font-size:13px; color:var(--muted); font-family:'Share Tech Mono',monospace;" id="currentStage">Initializing...</div>
        <div class="progress-bar-wrap">
          <div class="progress-bar-fill" id="progressBar"></div>
        </div>
      </div>

      <!-- Metric cards -->
      <div class="cards-grid" id="metricsGrid">
        <div class="metric-card critical-card">
          <div class="label">CRITICAL FLAGS</div>
          <div class="value" id="mc-critical">—</div>
          <div class="sub">Deterministic rules</div>
        </div>
        <div class="metric-card warn-card">
          <div class="label">WEB PATHS</div>
          <div class="value" id="mc-paths">—</div>
          <div class="sub">Feroxbuster discovered</div>
        </div>
        <div class="metric-card">
          <div class="label">NIKTO FINDINGS</div>
          <div class="value" id="mc-nikto">—</div>
          <div class="sub">Web vulnerabilities</div>
        </div>
        <div class="metric-card good-card">
          <div class="label">SECURE SCORE</div>
          <div class="value" id="mc-score">—</div>
          <div class="sub">Composite /100</div>
        </div>
      </div>

      <!-- Tabs -->
      <div class="tabs">
        <button class="tab-btn active" onclick="showTab('logs')">LIVE LOGS</button>
        <button class="tab-btn" onclick="showTab('overview')">RISK OVERVIEW</button>
        <button class="tab-btn" onclick="showTab('ferox')">WEB PATHS</button>
        <button class="tab-btn" onclick="showTab('enum')">ENUMERATION</button>
        <button class="tab-btn" onclick="showTab('nikto')">NIKTO</button>
        <button class="tab-btn" onclick="showTab('report')">REPORT</button>
      </div>

      <!-- Logs tab -->
      <div class="tab-content active" id="tab-logs">
        <div class="terminal" id="terminal"></div>
      </div>

      <!-- Overview tab -->
      <div class="tab-content" id="tab-overview">
        <div id="overviewContent">
          <p style="color:var(--muted);font-family:'Share Tech Mono',monospace;font-size:13px;">Scan in progress...</p>
        </div>
      </div>

      <!-- Ferox tab -->
      <div class="tab-content" id="tab-ferox">
        <div id="feroxContent">
          <p style="color:var(--muted);font-family:'Share Tech Mono',monospace;font-size:13px;">Waiting for Feroxbuster results...</p>
        </div>
      </div>

      <!-- Enum tab -->
      <div class="tab-content" id="tab-enum">
        <div id="enumContent">
          <p style="color:var(--muted);font-family:'Share Tech Mono',monospace;font-size:13px;">Waiting for enumeration results...</p>
        </div>
      </div>

      <!-- Nikto tab -->
      <div class="tab-content" id="tab-nikto">
        <div id="niktoContent">
          <p style="color:var(--muted);font-family:'Share Tech Mono',monospace;font-size:13px;">Waiting for Nikto results...</p>
        </div>
      </div>

      <!-- Report tab -->
      <div class="tab-content" id="tab-report">
        <div id="reportContent">
          <p style="color:var(--muted);font-family:'Share Tech Mono',monospace;font-size:13px;">Report generates at end of scan...</p>
        </div>
      </div>

    </div>
  </main>
</div>
</div>

<script>
let polling = null;
let scanRunning = false;

function showTab(name) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  event.target.classList.add('active');
}

function showAlert(msg, type) {
  const box = document.getElementById('alertBox');
  box.textContent = msg;
  box.className = 'alert ' + type;
  setTimeout(() => { box.className = 'alert'; }, 5000);
}

function startScan() {
  const target = document.getElementById('target').value.trim();
  if (!target) { showAlert('⚠ Enter a target IP or hostname', 'error'); return; }

  const port = document.getElementById('port').value || 80;
  const domain = document.getElementById('domain').value.trim();
  const safeMode = document.getElementById('safeMode').checked;

  document.getElementById('welcomeScreen').style.display = 'none';
  document.getElementById('resultsArea').style.display = 'block';
  document.getElementById('btnScan').disabled = true;
  document.getElementById('btnStop').style.display = 'block';
  document.getElementById('statusBadge').className = 'status-badge running';
  document.getElementById('statusBadge').textContent = 'SCANNING';
  document.getElementById('terminal').innerHTML = '';

  // Reset stages
  for (let i = 1; i <= 8; i++) {
    const el = document.getElementById('stage-' + i);
    el.className = 'stage-item';
  }

  scanRunning = true;

  fetch('/api/scan', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({target, port: parseInt(port), domain: domain || null, safe_mode: safeMode})
  })
  .then(r => r.json())
  .then(data => {
    if (data.error) { showAlert('Error: ' + data.error, 'error'); resetUI(); return; }
    polling = setInterval(pollStatus, 1500);
  })
  .catch(e => { showAlert('Connection error: ' + e, 'error'); resetUI(); });
}

function stopScan() {
  fetch('/api/stop', {method: 'POST'});
  clearInterval(polling);
  resetUI();
  showAlert('Scan stopped.', 'error');
}

function resetUI() {
  scanRunning = false;
  document.getElementById('btnScan').disabled = false;
  document.getElementById('btnStop').style.display = 'none';
  document.getElementById('statusBadge').className = 'status-badge';
  document.getElementById('statusBadge').textContent = 'STANDBY';
}

function pollStatus() {
  fetch('/api/status')
  .then(r => r.json())
  .then(data => {
    updateProgress(data.progress, data.stage);
    renderLogs(data.logs);
    updateStages(data.stage, data.progress);

    // Update metric cards as data comes in
    if (data.result) {
      updateMetrics(data.result);
      renderOverview(data.result);
      renderFerox(data.result);
      renderEnum(data.result);
      renderNikto(data.result);
      renderReport(data.result);
    }

    if (!data.running && data.progress >= 100) {
      clearInterval(polling);
      resetUI();
      document.getElementById('statusBadge').textContent = 'COMPLETE';
      document.getElementById('statusBadge').className = 'status-badge';
      document.getElementById('statusBadge').style.borderColor = 'var(--accent3)';
      document.getElementById('statusBadge').style.color = 'var(--accent3)';
      showAlert('✓ Scan complete! Report saved.', 'success');
    }

    if (data.error) {
      clearInterval(polling);
      resetUI();
      showAlert('Scan error: ' + data.error, 'error');
    }
  });
}

function updateProgress(pct, stage) {
  document.getElementById('progressBar').style.width = pct + '%';
  document.getElementById('currentStage').textContent = stage || 'Running...';
}

function updateStages(currentStage, progress) {
  const stageMap = {
    'strategy': 1, 'execution': 2, 'review': 3,
    'feroxbuster': 4, 'enumeration': 5, 'nikto': 6,
    'mitigation': 7, 'reporting': 8
  };
  const current = stageMap[currentStage] || 0;
  for (let i = 1; i <= 8; i++) {
    const el = document.getElementById('stage-' + i);
    if (i < current) el.className = 'stage-item done';
    else if (i === current) el.className = 'stage-item active';
    else el.className = 'stage-item';
  }
  if (progress >= 100) {
    for (let i = 1; i <= 8; i++) document.getElementById('stage-' + i).className = 'stage-item done';
  }
}

function renderLogs(logs) {
  const term = document.getElementById('terminal');
  term.innerHTML = logs.map(l => {
    const cls = l.level || 'INFO';
    return `<div class="log-line ${cls}"><span class="ts">${l.ts}</span><span class="msg">${escHtml(l.msg)}</span></div>`;
  }).join('');
  term.scrollTop = term.scrollHeight;
}

function updateMetrics(result) {
  if (result.feroxbuster) {
    document.getElementById('mc-paths').textContent = result.feroxbuster.discovered_count ?? '—';
    document.getElementById('mc-critical').textContent = result.feroxbuster.critical_count ?? '—';
  }
  if (result.nikto) {
    document.getElementById('mc-nikto').textContent = result.nikto.total_findings ?? '—';
  }
  if (result.mitigation) {
    document.getElementById('mc-score').textContent = result.mitigation.composite_secure_score ?? '—';
  }
}

function renderOverview(result) {
  if (!result.mitigation) return;
  const m = result.mitigation;
  const score = m.composite_secure_score || 0;
  const color = score >= 70 ? 'var(--accent3)' : score >= 50 ? 'var(--warn)' : 'var(--critical)';
  const issues = (m.detected_issues || []).map(i => `<tr><td>${escHtml(i)}</td></tr>`).join('') || '<tr><td style="color:var(--muted)">None detected</td></tr>';
  const steps = (m.mitigation_steps || []).map(s => `<li style="margin-bottom:8px">${escHtml(s)}</li>`).join('') || '<li style="color:var(--muted)">None</li>';

  document.getElementById('overviewContent').innerHTML = `
    <div class="score-display">
      <div class="score-circle" style="background: conic-gradient(${color} ${score * 3.6}deg, rgba(255,255,255,0.05) 0deg);">
        <div class="score-number" style="color:${color}">${score}</div>
        <div class="score-label">SCORE</div>
      </div>
      <div class="score-details">
        <div class="score-row"><span class="sname">RISK LEVEL</span><span class="sval" style="color:${color}">${m.risk_level || '—'}</span></div>
        <div class="score-row"><span class="sname">AI SCORE</span><span class="sval">${m.ai_secure_score || '—'}/100</span></div>
        <div class="score-row"><span class="sname">DETERMINISTIC</span><span class="sval">${m.deterministic_secure_score || '—'}/100</span></div>
        <div class="score-row"><span class="sname">COMPOSITE</span><span class="sval" style="color:${color}">${score}/100</span></div>
        <div class="score-row"><span class="sname">CONFIDENCE</span><span class="sval">${m.confidence_score || '—'}%</span></div>
      </div>
    </div>
    <div class="section-label">DETECTED ISSUES</div>
    <table class="findings-table" style="margin-bottom:24px">
      <tr><th>ISSUE</th></tr>
      ${issues}
    </table>
    <div class="section-label">MITIGATION STEPS</div>
    <ul style="padding-left:20px;line-height:2;color:var(--text)">${steps}</ul>
  `;
}

function renderFerox(result) {
  if (!result.feroxbuster) return;
  const f = result.feroxbuster;
  const paths = f.discovered_paths || [];
  const critical = f.critical_findings || [];

  const pathsHtml = paths.length > 0
    ? paths.map(p => {
        const sc = p.status_code;
        const cls = sc === 200 ? 's200' : sc === 301 || sc === 302 ? 's301' : sc === 403 ? 's403' : 's500';
        return `<div class="path-item"><span class="path-status ${cls}">${sc}</span><span class="path-url">${escHtml(p.path)}</span><span class="path-size">${p.size}b</span></div>`;
      }).join('')
    : '<p style="color:var(--muted);font-family:\'Share Tech Mono\',monospace;font-size:13px;padding:10px">No paths discovered</p>';

  const critHtml = critical.map(c => {
    const sev = c.includes('[CRITICAL]') ? 'CRITICAL' : c.includes('[HIGH]') ? 'HIGH' : c.includes('[MEDIUM]') ? 'MEDIUM' : 'LOW';
    return `<tr><td><span class="severity-badge sev-${sev}">${sev}</span></td><td>${escHtml(c.replace(/\[.*?\]\s*/, ''))}</td></tr>`;
  }).join('') || '<tr><td colspan="2" style="color:var(--muted)">None</td></tr>';

  document.getElementById('feroxContent').innerHTML = `
    <div class="cards-grid" style="margin-bottom:20px">
      <div class="metric-card"><div class="label">PATHS FOUND</div><div class="value">${f.discovered_count ?? 0}</div></div>
      <div class="metric-card critical-card"><div class="label">CRITICAL</div><div class="value">${f.critical_count ?? 0}</div></div>
      <div class="metric-card warn-card"><div class="label">WEB RISK SCORE</div><div class="value">${f.ai_analysis?.web_risk_score ?? '—'}</div></div>
    </div>
    <div class="section-label">CRITICAL FINDINGS</div>
    <table class="findings-table" style="margin-bottom:24px">
      <tr><th>SEVERITY</th><th>DESCRIPTION</th></tr>
      ${critHtml}
    </table>
    <div class="section-label">DISCOVERED PATHS (${paths.length})</div>
    <div class="paths-list">${pathsHtml}</div>
  `;
}

function renderEnum(result) {
  if (!result.enumeration) return;
  const e = result.enumeration;
  const ai = e.ai_analysis || {};
  const flags = e.critical_flags || [];

  const flagsHtml = flags.map(f => {
    const sev = f.includes('[CRITICAL]') ? 'CRITICAL' : f.includes('[HIGH]') ? 'HIGH' : f.includes('[MEDIUM]') ? 'MEDIUM' : 'LOW';
    return `<tr><td><span class="severity-badge sev-${sev}">${sev}</span></td><td>${escHtml(f.replace(/\[.*?\]\s*/, ''))}</td></tr>`;
  }).join('') || '<tr><td colspan="2" style="color:var(--muted)">None</td></tr>';

  const users = (e.parsed_users || ai.users_discovered || []).map(u => `<span style="font-family:'Share Tech Mono',monospace;background:rgba(0,212,255,0.1);padding:3px 10px;border-radius:3px;margin:3px;display:inline-block">${escHtml(u)}</span>`).join('') || '<span style="color:var(--muted)">None discovered</span>';

  const shares = (e.parsed_shares || []).map(s => `<tr><td style="font-family:'Share Tech Mono',monospace">${escHtml(s.name||s)}</td><td>${escHtml(s.type||'')}</td><td style="color:var(--muted)">${escHtml(s.comment||'')}</td></tr>`).join('')
    || (ai.shares_discovered||[]).map(s => `<tr><td colspan="3" style="font-family:'Share Tech Mono',monospace">${escHtml(s)}</td></tr>`).join('')
    || '<tr><td colspan="3" style="color:var(--muted)">None</td></tr>';

  const headers = (e.parsed_headers || ai.security_headers_missing || []).map(h => `<tr><td style="color:var(--critical)">❌ ${escHtml(h)}</td></tr>`).join('') || '<tr><td style="color:var(--accent3)">✓ No missing headers detected</td></tr>';

  document.getElementById('enumContent').innerHTML = `
    <div class="section-label">CRITICAL FLAGS</div>
    <table class="findings-table" style="margin-bottom:24px">
      <tr><th>SEVERITY</th><th>DESCRIPTION</th></tr>
      ${flagsHtml}
    </table>
    <div class="section-label">USERS DISCOVERED (SMB)</div>
    <div style="margin-bottom:24px;padding:14px;background:var(--panel);border:1px solid var(--border);border-radius:8px">${users}</div>
    <div class="section-label">SMB SHARES</div>
    <table class="findings-table" style="margin-bottom:24px">
      <tr><th>SHARE NAME</th><th>TYPE</th><th>COMMENT</th></tr>
      ${shares}
    </table>
    <div class="section-label">MISSING SECURITY HEADERS</div>
    <table class="findings-table" style="margin-bottom:24px">
      <tr><th>HEADER</th></tr>
      ${headers}
    </table>
    <div class="section-label">ATTACK SURFACE SUMMARY</div>
    <p style="color:var(--text);line-height:1.8;padding:14px;background:var(--panel);border:1px solid var(--border);border-radius:8px">${escHtml(ai.attack_surface_summary || '—')}</p>
  `;
}

function renderNikto(result) {
  if (!result.nikto) return;
  const n = result.nikto;
  const ai = n.ai_analysis || {};

  const flags = (n.critical_flags || []).map(f => {
    const sev = f.includes('[CRITICAL]') ? 'CRITICAL' : f.includes('[HIGH]') ? 'HIGH' : f.includes('[MEDIUM]') ? 'MEDIUM' : f.includes('[INFO]') ? 'INFO' : 'LOW';
    return `<tr><td><span class="severity-badge sev-${sev}">${sev}</span></td><td>${escHtml(f.replace(/\[.*?\]\s*/, ''))}</td></tr>`;
  }).join('') || '<tr><td colspan="2" style="color:var(--muted)">None</td></tr>';

  const remed = (ai.remediation_priority || []).map(r =>
    `<tr><td><span class="severity-badge sev-${r.priority?.toUpperCase()}">${r.priority}</span></td><td>${escHtml(r.issue)}</td><td>${escHtml(r.fix)}</td></tr>`
  ).join('') || '<tr><td colspan="3" style="color:var(--muted)">No data</td></tr>';

  const osvdb = (n.osvdb_ids || []).map(o => `<span style="font-family:'Share Tech Mono',monospace;background:rgba(255,60,110,0.1);padding:3px 8px;border-radius:3px;margin:3px;display:inline-block;color:var(--critical)">${escHtml(o)}</span>`).join('') || '<span style="color:var(--muted)">None</span>';

  document.getElementById('niktoContent').innerHTML = `
    <div class="cards-grid" style="margin-bottom:20px">
      <div class="metric-card critical-card"><div class="label">TOTAL FINDINGS</div><div class="value">${n.total_findings ?? '—'}</div></div>
      <div class="metric-card warn-card"><div class="label">NIKTO RISK SCORE</div><div class="value">${ai.nikto_risk_score ?? '—'}</div></div>
      <div class="metric-card"><div class="label">OSVDB/CVE REFS</div><div class="value">${(n.osvdb_ids||[]).length}</div></div>
    </div>
    <div style="padding:14px;background:rgba(255,60,110,0.07);border:1px solid rgba(255,60,110,0.2);border-radius:8px;margin-bottom:24px;font-style:italic;color:var(--text)">
      ⚡ <strong>Executive Finding:</strong> ${escHtml(ai.executive_finding || '—')}
    </div>
    <div class="section-label">OSVDB / CVE REFERENCES</div>
    <div style="margin-bottom:24px;padding:14px;background:var(--panel);border:1px solid var(--border);border-radius:8px">${osvdb}</div>
    <div class="section-label">DETERMINISTIC FLAGS</div>
    <table class="findings-table" style="margin-bottom:24px">
      <tr><th>SEVERITY</th><th>DESCRIPTION</th></tr>
      ${flags}
    </table>
    <div class="section-label">REMEDIATION PRIORITY TABLE</div>
    <table class="findings-table">
      <tr><th>PRIORITY</th><th>ISSUE</th><th>FIX</th></tr>
      ${remed}
    </table>
  `;
}

function renderReport(result) {
  if (!result.report_path) return;
  document.getElementById('reportContent').innerHTML = `
    <div style="padding:20px;background:var(--panel);border:1px solid var(--accent3);border-radius:8px;margin-bottom:20px">
      <div style="color:var(--accent3);font-family:'Share Tech Mono',monospace;font-size:13px;margin-bottom:8px">✓ REPORT SAVED</div>
      <div style="color:var(--text);font-family:'Share Tech Mono',monospace;font-size:12px;word-break:break-all">${escHtml(result.report_path)}</div>
    </div>
    <a href="/api/report" target="_blank" style="display:inline-block;padding:12px 28px;border:2px solid var(--accent);border-radius:6px;color:var(--accent);font-family:'Rajdhani',sans-serif;font-size:15px;font-weight:700;letter-spacing:3px;text-decoration:none;transition:all 0.2s" onmouseover="this.style.background='var(--accent)';this.style.color='var(--bg)'" onmouseout="this.style.background='transparent';this.style.color='var(--accent)'">📄 VIEW MARKDOWN REPORT</a>
  `;
}

function escHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
</script>
</body>
</html>
"""

# ── API routes ────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route("/api/scan", methods=["POST"])
def api_scan():
    global scan_status
    if scan_status["running"]:
        return jsonify({"error": "Scan already running"}), 400

    data = request.json
    target = data.get("target", "").strip()
    port = int(data.get("port", 80))
    domain = data.get("domain") or None
    safe_mode = data.get("safe_mode", True)

    if not target:
        return jsonify({"error": "Target is required"}), 400

    # Reset state
    scan_status = {
        "running": True,
        "stage": "strategy",
        "progress": 0,
        "logs": [],
        "result": {},
        "error": None,
    }

    # Run pipeline in background thread
    thread = threading.Thread(
        target=run_scan_pipeline,
        args=(target, port, domain, safe_mode),
        daemon=True,
    )
    thread.start()
    return jsonify({"status": "started"})


@app.route("/api/status")
def api_status():
    return jsonify(scan_status)


@app.route("/api/stop", methods=["POST"])
def api_stop():
    scan_status["running"] = False
    return jsonify({"status": "stopped"})


@app.route("/api/report")
def api_report():
    path = scan_status.get("result", {}).get("report_path")
    if not path or not os.path.exists(path):
        return "No report available yet.", 404
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    # Render as preformatted text
    html = f"<html><body style='background:#090e14;color:#c8e0f0;font-family:monospace;padding:30px;white-space:pre-wrap'>{content}</body></html>"
    return html


# ── Pipeline runner ───────────────────────────────────────────────────────────

def log(msg, level="INFO"):
    ts = datetime.now().strftime("%H:%M:%S")
    scan_status["logs"].append({"ts": ts, "msg": msg, "level": level})
    if len(scan_status["logs"]) > 500:
        scan_status["logs"] = scan_status["logs"][-500:]


def run_scan_pipeline(target, port, domain, safe_mode):
    try:
        # Override safe mode in env temporarily
        os.environ["SAFE_MODE"] = "false" if not safe_mode else "true"

        from core.config import get_settings
        get_settings.cache_clear()

        from core.config import configure_logging, settings
        from core.llm_client import LLMClient
        from core.memory import AgentMemory
        from core.risk_engine import RiskEngine
        from agents.strategy_agent import StrategyAgent
        from agents.execution_agent import ExecutionAgent
        from agents.review_agent import ReviewAgent
        from agents.mitigation_agent import MitigationAgent
        from agents.reporting_agent import ReportingAgent
        from agents.feroxbuster_agent import FeroxbusterAgent
        from agents.enumeration_agent import EnumerationAgent
        from agents.nikto_agent import NiktoAgent

        memory = AgentMemory()
        llm = LLMClient()
        risk_engine = RiskEngine()

        # Stage 1
        scan_status["stage"] = "strategy"
        scan_status["progress"] = 5
        log(f"[1/8] StrategyAgent — Generating scan command for {target}", "STAGE")
        strategy_agent = StrategyAgent(llm_client=llm, memory=memory)
        scan_command = strategy_agent.run(target=target)
        log(f"✓ Command: {scan_command}", "SUCCESS")

        # Stage 2
        scan_status["stage"] = "execution"
        scan_status["progress"] = 18
        log("[2/8] ExecutionAgent — Running nmap scan...", "STAGE")
        exec_agent = ExecutionAgent(llm_client=llm, memory=memory)
        exec_result = exec_agent.run(command=scan_command)
        log(f"✓ Nmap complete ({len(exec_result.stdout)} chars output)", "SUCCESS")
        if exec_result.safe_mode:
            log("⚠ SAFE_MODE=true — using mock nmap output", "WARNING")

        # Stage 3
        scan_status["stage"] = "review"
        scan_status["progress"] = 30
        log("[3/8] ReviewAgent — Evaluating scan completeness...", "STAGE")
        review_agent = ReviewAgent(llm_client=llm, memory=memory)
        needs_rescan = review_agent.run(scan_output=exec_result.stdout)
        log(f"✓ Review: {'Re-scan recommended' if needs_rescan else 'Scan sufficient'}", "SUCCESS")

        # Stage 4
        scan_status["stage"] = "feroxbuster"
        scan_status["progress"] = 42
        log("[4/8] FeroxbusterAgent — Web directory brute-force...", "STAGE")
        ferox_agent = FeroxbusterAgent(llm_client=llm, memory=memory)
        ferox_obj = ferox_agent.run(target=target, port=port)
        ferox_data = memory.retrieve("feroxbuster_result")
        scan_status["result"]["feroxbuster"] = ferox_data
        log(f"✓ Feroxbuster: {len(ferox_obj.discovered_paths)} paths | {len(ferox_obj.critical_findings)} critical", "SUCCESS")

        # Stage 5
        scan_status["stage"] = "enumeration"
        scan_status["progress"] = 55
        log("[5/8] EnumerationAgent — SMB/DNS/HTTP/SNMP...", "STAGE")
        enum_agent = EnumerationAgent(llm_client=llm, memory=memory)
        enum_obj = enum_agent.run(target=target, domain=domain, port=port)
        enum_data = memory.retrieve("enumeration_result")
        scan_status["result"]["enumeration"] = enum_data
        log(f"✓ Enumeration: {len(enum_obj.critical_flags)} flags", "SUCCESS")

        # Stage 6
        scan_status["stage"] = "nikto"
        scan_status["progress"] = 68
        log("[6/8] NiktoAgent — Web vulnerability scanning...", "STAGE")
        nikto_agent = NiktoAgent(llm_client=llm, memory=memory)
        nikto_obj = nikto_agent.run(target=target, port=port)
        nikto_data = memory.retrieve("nikto_result")
        scan_status["result"]["nikto"] = nikto_data
        log(f"✓ Nikto: {nikto_obj.total_findings} findings | {len(nikto_obj.osvdb_ids)} OSVDB refs", "SUCCESS")

        # Stage 7
        scan_status["stage"] = "mitigation"
        scan_status["progress"] = 82
        log("[7/8] MitigationAgent — AI risk classification...", "STAGE")
        combined = (
            exec_result.stdout + "\n" +
            ferox_obj.raw_output + "\n" +
            enum_obj.smb_output + "\n" +
            nikto_obj.raw_output
        )
        mitigation_agent = MitigationAgent(llm_client=llm, memory=memory, risk_engine=risk_engine)
        mitigation_report = mitigation_agent.run(scan_output=combined)
        scan_status["result"]["mitigation"] = mitigation_report
        log(f"✓ Risk Level: {mitigation_report.get('risk_level','?')} | Score: {mitigation_report.get('composite_secure_score','?')}/100", "SUCCESS")

        # Stage 8
        scan_status["stage"] = "reporting"
        scan_status["progress"] = 93
        log("[8/8] ReportingAgent — Generating Markdown report...", "STAGE")
        reporting_agent = ReportingAgent(llm_client=llm, memory=memory)
        report_path = reporting_agent.run(
            target=target,
            scan_command=scan_command,
            scan_output=exec_result.stdout,
            mitigation=mitigation_report,
            feroxbuster_result=ferox_data,
            enumeration_result=enum_data,
            nikto_result=nikto_data,
        )
        scan_status["result"]["report_path"] = report_path
        log(f"✓ Report saved: {report_path}", "SUCCESS")

        scan_status["progress"] = 100
        scan_status["stage"] = "complete"
        scan_status["running"] = False
        log("🛡 AI-SecureScan pipeline complete!", "SUCCESS")

    except Exception as e:
        log(f"Pipeline error: {e}", "ERROR")
        scan_status["error"] = str(e)
        scan_status["running"] = False


if __name__ == "__main__":
    print("\n🛡  AI-SecureScan Web Dashboard")
    print("   Open: http://localhost:5000\n")
    app.run(host="0.0.0.0", port=5000, debug=False)
