#!/usr/bin/env python3
"""
Enhanced Security Scanner - Dashboard API
Flask API for SonarQube-equivalent dashboard functionality
"""

from flask import Flask, request, jsonify, render_template_string, send_file
from flask_cors import CORS
import json
import os
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import uuid
import tempfile
from pathlib import Path

# Import our main scanner components
from security_scanner_main import (
    SecurityScanner, SecurityRule, QualityGate, SecurityIssue,
    MetricsCalculator, ScanResult
)

app = Flask(__name__)
CORS(app)

# Initialize scanner
scanner = SecurityScanner()

# Dashboard HTML template
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scanner Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; }
        .header { background: #2c3e50; color: white; padding: 1rem 2rem; display: flex; justify-content: between; align-items: center; }
        .nav { display: flex; gap: 2rem; }
        .nav a { color: white; text-decoration: none; padding: 0.5rem 1rem; border-radius: 4px; }
        .nav a:hover { background: rgba(255,255,255,0.1); }
        .container { max-width: 1200px; margin: 2rem auto; padding: 0 2rem; }
        .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }
        .metric-card { background: white; padding: 1.5rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .metric-value { font-size: 2rem; font-weight: bold; margin-bottom: 0.5rem; }
        .metric-label { color: #666; font-size: 0.9rem; }
        .rating-A { color: #27ae60; }
        .rating-B { color: #f39c12; }
        .rating-C { color: #e67e22; }
        .rating-D { color: #e74c3c; }
        .rating-E { color: #c0392b; }
        .quality-gate-OK { color: #27ae60; }
        .quality-gate-WARN { color: #f39c12; }
        .quality-gate-ERROR { color: #e74c3c; }
        .section { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 2rem; }
        .section h2 { margin-bottom: 1rem; color: #2c3e50; }
        .issues-table { width: 100%; border-collapse: collapse; }
        .issues-table th, .issues-table td { padding: 0.75rem; text-align: left; border-bottom: 1px solid #eee; }
        .issues-table th { background: #f8f9fa; font-weight: 600; }
        .severity-BLOCKER { background: #c0392b; color: white; padding: 0.25rem 0.5rem; border-radius: 3px; font-size: 0.8rem; }
        .severity-CRITICAL { background: #e74c3c; color: white; padding: 0.25rem 0.5rem; border-radius: 3px; font-size: 0.8rem; }
        .severity-MAJOR { background: #f39c12; color: white; padding: 0.25rem 0.5rem; border-radius: 3px; font-size: 0.8rem; }
        .severity-MINOR { background: #3498db; color: white; padding: 0.25rem 0.5rem; border-radius: 3px; font-size: 0.8rem; }
        .severity-INFO { background: #95a5a6; color: white; padding: 0.25rem 0.5rem; border-radius: 3px; font-size: 0.8rem; }
        .btn { padding: 0.5rem 1rem; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; }
        .btn-primary { background: #3498db; color: white; }
        .btn-success { background: #27ae60; color: white; }
        .btn-danger { background: #e74c3c; color: white; }
        .btn:hover { opacity: 0.9; }
        .tabs { display: flex; border-bottom: 1px solid #ddd; margin-bottom: 1rem; }
        .tab { padding: 1rem 2rem; cursor: pointer; border-bottom: 2px solid transparent; }
        .tab.active { border-bottom-color: #3498db; background: #f8f9fa; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .chart-container { height: 300px; margin: 1rem 0; }
        .form-group { margin-bottom: 1rem; }
        .form-group label { display: block; margin-bottom: 0.5rem; font-weight: 600; }
        .form-group input, .form-group select, .form-group textarea { width: 100%; padding: 0.5rem; border: 1px solid #ddd; border-radius: 4px; }
        .form-group textarea { height: 100px; }
        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 1000; }
        .modal-content { background: white; margin: 5% auto; padding: 2rem; width: 80%; max-width: 600px; border-radius: 8px; }
        .close { float: right; font-size: 1.5rem; cursor: pointer; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Scanner Dashboard</h1>
        <nav class="nav">
            <a href="#" onclick="showTab('overview')">Overview</a>
            <a href="#" onclick="showTab('issues')">Issues</a>
            <a href="#" onclick="showTab('rules')">Rules</a>
            <a href="#" onclick="showTab('quality-gates')">Quality Gates</a>
            <a href="#" onclick="showTab('activity')">Activity</a>
            <a href="#" onclick="showTab('administration')">Administration</a>
        </nav>
    </div>

    <div class="container">
        <!-- Overview Tab -->
        <div id="overview-tab" class="tab-content active">
            <div class="metrics-grid">
                <div class="metric-card">
                    <div class="metric-value rating-{{security_rating}}" id="security-rating">{{security_rating}}</div>
                    <div class="metric-label">Security Rating</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value rating-{{reliability_rating}}" id="reliability-rating">{{reliability_rating}}</div>
                    <div class="metric-label">Reliability Rating</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value rating-{{maintainability_rating}}" id="maintainability-rating">{{maintainability_rating}}</div>
                    <div class="metric-label">Maintainability Rating</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value quality-gate-{{quality_gate_status}}" id="quality-gate-status">{{quality_gate_status}}</div>
                    <div class="metric-label">Quality Gate</div>
                </div>
            </div>

            <div class="metrics-grid">
                <div class="metric-card">
                    <div class="metric-value" id="total-issues">{{total_issues}}</div>
                    <div class="metric-label">Total Issues</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value" id="files-scanned">{{files_scanned}}</div>
                    <div class="metric-label">Files Scanned</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value" id="lines-of-code">{{lines_of_code}}</div>
                    <div class="metric-label">Lines of Code</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value" id="technical-debt">{{technical_debt}}h</div>
                    <div class="metric-label">Technical Debt</div>
                </div>
            </div>

            <div class="section">
                <h2>Recent Issues</h2>
                <table class="issues-table">
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Type</th>
                            <th>Rule</th>
                            <th>File</th>
                            <th>Line</th>
                            <th>Message</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="recent-issues">
                        <!-- Issues will be loaded here -->
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Issues Tab -->
        <div id="issues-tab" class="tab-content">
            <div class="section">
                <h2>Security Issues</h2>
                <div style="margin-bottom: 1rem;">
                    <select id="severity-filter" onchange="filterIssues()">
                        <option value="">All Severities</option>
                        <option value="BLOCKER">Blocker</option>
                        <option value="CRITICAL">Critical</option>
                        <option value="MAJOR">Major</option>
                        <option value="MINOR">Minor</option>
                        <option value="INFO">Info</option>
                    </select>
                    <select id="status-filter" onchange="filterIssues()">
                        <option value="">All Statuses</option>
                        <option value="OPEN">Open</option>
                        <option value="CONFIRMED">Confirmed</option>
                        <option value="RESOLVED">Resolved</option>
                        <option value="FALSE_POSITIVE">False Positive</option>
                    </select>
                </div>
                <table class="issues-table">
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Type</th>
                            <th>Rule</th>
                            <th>File</th>
                            <th>Line</th>
                            <th>Status</th>
                            <th>Message</th>
                            <th>Suggested Fix</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="all-issues">
                        <!-- All issues will be loaded here -->
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Rules Tab -->
        <div id="rules-tab" class="tab-content">
            <div class="section">
                <h2>Security Rules</h2>
                <button class="btn btn-primary" onclick="showCreateRuleModal()">Create New Rule</button>
                <table class="issues-table" style="margin-top: 1rem;">
                    <thead>
                        <tr>
                            <th>Rule ID</th>
                            <th>Name</th>
                            <th>Language</th>
                            <th>Severity</th>
                            <th>Type</th>
                            <th>Enabled</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="rules-list">
                        <!-- Rules will be loaded here -->
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Quality Gates Tab -->
        <div id="quality-gates-tab" class="tab-content">
            <div class="section">
                <h2>Quality Gates</h2>
                <button class="btn btn-primary" onclick="showCreateGateModal()">Create New Quality Gate</button>
                <div id="quality-gates-list" style="margin-top: 1rem;">
                    <!-- Quality gates will be loaded here -->
                </div>
            </div>
        </div>

        <!-- Activity Tab -->
        <div id="activity-tab" class="tab-content">
            <div class="section">
                <h2>Scan Activity</h2>
                <div class="chart-container" id="activity-chart">
                    <!-- Activity chart will be rendered here -->
                </div>
                <table class="issues-table">
                    <thead>
                        <tr>
                            <th>Scan Date</th>
                            <th>Project</th>
                            <th>Files</th>
                            <th>Issues</th>
                            <th>Duration</th>
                            <th>Quality Gate</th>
                        </tr>
                    </thead>
                    <tbody id="scan-history">
                        <!-- Scan history will be loaded here -->
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Administration Tab -->
        <div id="administration-tab" class="tab-content">
            <div class="section">
                <h2>Project Administration</h2>
                <div class="form-group">
                    <label for="project-path">Project Path:</label>
                    <input type="text" id="project-path" placeholder="/path/to/project">
                </div>
                <div class="form-group">
                    <label for="project-id">Project ID:</label>
                    <input type="text" id="project-id" placeholder="my-project">
                </div>
                <button class="btn btn-primary" onclick="scanProject()">Start New Scan</button>
                <button class="btn btn-danger" onclick="exportData()">Export Data</button>
            </div>
        </div>
    </div>

    <!-- Create Rule Modal -->
    <div id="create-rule-modal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal('create-rule-modal')">&times;</span>
            <h2>Create New Security Rule</h2>
            <form onsubmit="createRule(event)">
                <div class="form-group">
                    <label for="rule-id">Rule ID:</label>
                    <input type="text" id="rule-id" required>
                </div>
                <div class="form-group">
                    <label for="rule-name">Name:</label>
                    <input type="text" id="rule-name" required>
                </div>
                <div class="form-group">
                    <label for="rule-description">Description:</label>
                    <textarea id="rule-description" required></textarea>
                </div>
                <div class="form-group">
                    <label for="rule-severity">Severity:</label>
                    <select id="rule-severity" required>
                        <option value="BLOCKER">Blocker</option>
                        <option value="CRITICAL">Critical</option>
                        <option value="MAJOR">Major</option>
                        <option value="MINOR">Minor</option>
                        <option value="INFO">Info</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="rule-type">Type:</label>
                    <select id="rule-type" required>
                        <option value="VULNERABILITY">Vulnerability</option>
                        <option value="BUG">Bug</option>
                        <option value="CODE_SMELL">Code Smell</option>
                        <option value="SECURITY_HOTSPOT">Security Hotspot</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="rule-language">Language:</label>
                    <select id="rule-language" required>
                        <option value="*">All Languages</option>
                        <option value="python">Python</option>
                        <option value="javascript">JavaScript</option>
                        <option value="java">Java</option>
                        <option value="csharp">C#</option>
                        <option value="php">PHP</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="rule-pattern">Regex Pattern:</label>
                    <input type="text" id="rule-pattern" required>
                </div>
                <div class="form-group">
                    <label for="rule-effort">Remediation Effort (minutes):</label>
                    <input type="number" id="rule-effort" value="30" required>
                </div>
                <button type="submit" class="btn btn-success">Create Rule</button>
            </form>
        </div>
    </div>

    <script>
        let currentData = {};

        // Load initial data
        document.addEventListener('DOMContentLoaded', function() {
            loadDashboardData();
        });

        function showTab(tabName) {
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Show selected tab
            document.getElementById(tabName + '-tab').classList.add('active');
            
            // Load tab-specific data
            switch(tabName) {
                case 'issues':
                    loadAllIssues();
                    break;
                case 'rules':
                    loadRules();
                    break;
                case 'quality-gates':
                    loadQualityGates();
                    break;
                case 'activity':
                    loadActivity();
                    break;
            }
        }

        async function loadDashboardData() {
            try {
                const response = await fetch('/api/dashboard/metrics');
                const data = await response.json();
                currentData = data;
                
                if (data.error) {
                    console.error('No scan data available');
                    return;
                }
                
                updateOverviewMetrics(data);
                loadRecentIssues(data.recent_issues || []);
            } catch (error) {
                console.error('Error loading dashboard data:', error);
            }
        }

        function updateOverviewMetrics(data) {
            const metrics = data.scan_info;
            const ratings = data.ratings;
            const qualityGate = data.quality_gate;
            const issues = data.issues;
            
            document.getElementById('security-rating').textContent = ratings.security;
            document.getElementById('reliability-rating').textContent = ratings.reliability;
            document.getElementById('maintainability-rating').textContent = ratings.maintainability;
            document.getElementById('quality-gate-status').textContent = qualityGate.status;
            
            document.getElementById('total-issues').textContent = issues.total;
            document.getElementById('files-scanned').textContent = metrics.files_scanned;
            document.getElementById('lines-of-code').textContent = metrics.lines_of_code.toLocaleString();
            document.getElementById('technical-debt').textContent = Math.round(data.metrics.technical_debt / 60);
        }

        function loadRecentIssues(issues) {
            const tbody = document.getElementById('recent-issues');
            tbody.innerHTML = '';
            
            issues.slice(0, 10).forEach(issue => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td><span class="severity-${issue.severity}">${issue.severity}</span></td>
                    <td>${issue.type}</td>
                    <td>${issue.rule_id}</td>
                    <td>${issue.file_path.split('/').pop()}</td>
                    <td>${issue.line_number}</td>
                    <td>${issue.message}</td>
                    <td>
                        <button class="btn btn-primary" onclick="showIssueDetails('${issue.id}')">Details</button>
                        <button class="btn btn-success" onclick="resolveIssue('${issue.id}')">Resolve</button>
                    </td>
                `;
                tbody.appendChild(row);
            });
        }

        async function loadAllIssues() {
            try {
                const response = await fetch('/api/issues');
                const issues = await response.json();
                
                const tbody = document.getElementById('all-issues');
                tbody.innerHTML = '';
                
                issues.forEach(issue => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td><span class="severity-${issue.severity}">${issue.severity}</span></td>
                        <td>${issue.type}</td>
                        <td>${issue.rule_id}</td>
                        <td>${issue.file_path.split('/').pop()}</td>
                        <td>${issue.line_number}</td>
                        <td>${issue.status}</td>
                        <td>${issue.message}</td>
                        <td>${issue.suggested_fix || 'N/A'}</td>
                        <td>
                            <button class="btn btn-primary" onclick="showIssueDetails('${issue.id}')">Details</button>
                            <select onchange="updateIssueStatus('${issue.id}', this.value)">
                                <option value="">Change Status</option>
                                <option value="OPEN">Open</option>
                                <option value="CONFIRMED">Confirmed</option>
                                <option value="RESOLVED">Resolved</option>
                                <option value="FALSE_POSITIVE">False Positive</option>
                            </select>
                        </td>
                    `;
                    tbody.appendChild(row);
                });
            } catch (error) {
                console.error('Error loading issues:', error);
            }
        }

        async function loadRules() {
            try {
                const response = await fetch('/api/rules');
                const rules = await response.json();
                
                const tbody = document.getElementById('rules-list');
                tbody.innerHTML = '';
                
                Object.values(rules).forEach(rule => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${rule.id}</td>
                        <td>${rule.name}</td>
                        <td>${rule.language}</td>
                        <td><span class="severity-${rule.severity}">${rule.severity}</span></td>
                        <td>${rule.type}</td>
                        <td>${rule.enabled ? 'Yes' : 'No'}</td>
                        <td>
                            <button class="btn btn-primary" onclick="editRule('${rule.id}')">Edit</button>
                            <button class="btn btn-danger" onclick="deleteRule('${rule.id}')">Delete</button>
                            <button class="btn ${rule.enabled ? 'btn-danger' : 'btn-success'}" 
                                    onclick="toggleRule('${rule.id}', ${!rule.enabled})">
                                ${rule.enabled ? 'Disable' : 'Enable'}
                            </button>
                        </td>
                    `;
                    tbody.appendChild(row);
                });
            } catch (error) {
                console.error('Error loading rules:', error);
            }
        }

        async function loadQualityGates() {
            try {
                const response = await fetch('/api/quality-gates');
                const gates = await response.json();
                
                const container = document.getElementById('quality-gates-list');
                container.innerHTML = '';
                
                Object.values(gates).forEach(gate => {
                    const gateDiv = document.createElement('div');
                    gateDiv.className = 'section';
                    gateDiv.innerHTML = `
                        <h3>${gate.name} ${gate.is_default ? '(Default)' : ''}</h3>
                        <p>Conditions: ${gate.conditions.length}</p>
                        <button class="btn btn-primary" onclick="editQualityGate('${gate.id}')">Edit</button>
                        <button class="btn btn-danger" onclick="deleteQualityGate('${gate.id}')">Delete</button>
                    `;
                    container.appendChild(gateDiv);
                });
            } catch (error) {
                console.error('Error loading quality gates:', error);
            }
        }

        async function loadActivity() {
            try {
                const response = await fetch('/api/scan-history');
                const scans = await response.json();
                
                const tbody = document.getElementById('scan-history');
                tbody.innerHTML = '';
                
                scans.forEach(scan => {
                    const row = document.createElement('tr');
                    const scanDate = new Date(scan.timestamp).toLocaleString();
                    row.innerHTML = `
                        <td>${scanDate}</td>
                        <td>${scan.project_id}</td>
                        <td>${scan.files_scanned}</td>
                        <td>${scan.issues.length}</td>
                        <td>${scan.duration_ms}ms</td>
                        <td><span class="quality-gate-${scan.quality_gate_status}">${scan.quality_gate_status}</span></td>
                    `;
                    tbody.appendChild(row);
                });
            } catch (error) {
                console.error('Error loading activity:', error);
            }
        }

        async function scanProject() {
            const projectPath = document.getElementById('project-path').value;
            const projectId = document.getElementById('project-id').value;
            
            if (!projectPath || !projectId) {
                alert('Please enter both project path and project ID');
                return;
            }
            
            try {
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ project_path: projectPath, project_id: projectId })
                });
                
                const result = await response.json();
                
                if (response.ok) {
                    alert('Scan completed successfully!');
                    loadDashboardData();
                } else {
                    alert('Scan failed: ' + result.error);
                }
            } catch (error) {
                console.error('Error starting scan:', error);
                alert('Error starting scan');
            }
        }

        async function createRule(event) {
            event.preventDefault();
            
            const ruleData = {
                id: document.getElementById('rule-id').value,
                name: document.getElementById('rule-name').value,
                description: document.getElementById('rule-description').value,
                severity: document.getElementById('rule-severity').value,
                type: document.getElementById('rule-type').value,
                language: document.getElementById('rule-language').value,
                pattern: document.getElementById('rule-pattern').value,
                remediation_effort: parseInt(document.getElementById('rule-effort').value),
                tags: ['custom'],
                enabled: true,
                custom: true
            };
            
            try {
                const response = await fetch('/api/rules', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(ruleData)
                });
                
                if (response.ok) {
                    alert('Rule created successfully!');
                    closeModal('create-rule-modal');
                    loadRules();
                } else {
                    const error = await response.json();
                    alert('Error creating rule: ' + error.error);
                }
            } catch (error) {
                console.error('Error creating rule:', error);
                alert('Error creating rule');
            }
        }

        async function updateIssueStatus(issueId, status) {
            if (!status) return;
            
            try {
                const response = await fetch(`/api/issues/${issueId}/status`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ status: status })
                });
                
                if (response.ok) {
                    loadAllIssues();
                    loadDashboardData();
                } else {
                    alert('Error updating issue status');
                }
            } catch (error) {
                console.error('Error updating issue status:', error);
            }
        }

        async function toggleRule(ruleId, enabled) {
            try {
                const response = await fetch(`/api/rules/${ruleId}`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ enabled: enabled })
                });
                
                if (response.ok) {
                    loadRules();
                } else {
                    alert('Error updating rule');
                }
            } catch (error) {
                console.error('Error updating rule:', error);
            }
        }

        function showCreateRuleModal() {
            document.getElementById('create-rule-modal').style.display = 'block';
        }

        function closeModal(modalId) {
            document.getElementById(modalId).style.display = 'none';
        }

        function filterIssues() {
            const severityFilter = document.getElementById('severity-filter').value;
            const statusFilter = document.getElementById('status-filter').value;
            
            const rows = document.querySelectorAll('#all-issues tr');
            rows.forEach(row => {
                const severity = row.cells[0].textContent.trim();
                const status = row.cells[5].textContent.trim();
                
                const severityMatch = !severityFilter || severity === severityFilter;
                const statusMatch = !statusFilter || status === statusFilter;
                
                row.style.display = (severityMatch && statusMatch) ? '' : 'none';
            });
        }

        function showIssueDetails(issueId) {
            // Implementation for showing issue details modal
            alert('Issue details for: ' + issueId);
        }

        function resolveIssue(issueId) {
            updateIssueStatus(issueId, 'RESOLVED');
        }

        async function exportData() {
            try {
                const response = await fetch('/api/export');
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'security_scan_data.json';
                a.click();
                window.URL.revokeObjectURL(url);
            } catch (error) {
                console.error('Error exporting data:', error);
            }
        }
    </script>
</body>
</html>
"""

@app.route('/')
def dashboard():
    """Serve the main dashboard"""
    return render_template_string(DASHBOARD_HTML)

@app.route('/api/dashboard/metrics')
def get_dashboard_metrics():
    """Get dashboard metrics"""
    try:
        metrics = scanner.get_dashboard_metrics()
        
        # Add recent issues to the response
        if not metrics.get('error'):
            recent_issues = []
            for scan in scanner.scan_history[-5:]:  # Last 5 scans
                recent_issues.extend([
                    {
                        'id': issue.id,
                        'rule_id': issue.rule_id,
                        'file_path': issue.file_path,
                        'line_number': issue.line_number,
                        'message': issue.message,
                        'severity': issue.severity,
                        'type': issue.type,
                        'status': issue.status,
                        'suggested_fix': issue.suggested_fix
                    }
                    for issue in scan.issues[:10]  # Top 10 issues per scan
                ])
            
            metrics['recent_issues'] = recent_issues[-20:]  # Last 20 issues
        
        return jsonify(metrics)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a new security scan"""
    try:
        data = request.get_json()
        project_path = data.get('project_path')
        project_id = data.get('project_id')
        
        if not project_path or not project_id:
            return jsonify({'error': 'Missing project_path or project_id'}), 400
        
        if not os.path.exists(project_path):
            return jsonify({'error': 'Project path does not exist'}), 400
        
        # Start scan
        result = scanner.scan_project(project_path, project_id)
        
        return jsonify({
            'scan_id': result.scan_id,
            'project_id': result.project_id,
            'timestamp': result.timestamp,
            'files_scanned': result.files_scanned,
            'issues_found': len(result.issues),
            'duration_ms': result.duration_ms,
            'quality_gate_status': result.quality_gate_status
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/issues')
def get_issues():
    """Get all security issues"""
    try:
        issues = []
        for issue in scanner.issue_manager.issues.values():
            issues.append({
                'id': issue.id,
                'rule_id': issue.rule_id,
                'file_path': issue.file_path,
                'line_number': issue.line_number,
                'column': issue.column,
                'message': issue.message,
                'severity': issue.severity,
                'type': issue.type,
                'status': issue.status,
                'assignee': issue.assignee,
                'creation_date': issue.creation_date,
                'update_date': issue.update_date,
                'effort': issue.effort,
                'code_snippet': issue.code_snippet,
                'suggested_fix': issue.suggested_fix
            })
        
        return jsonify(issues)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/issues/<issue_id>/status', methods=['PUT'])
def update_issue_status(issue_id):
    """Update issue status"""
    try:
        data = request.get_json()
        status = data.get('status')
        assignee = data.get('assignee')
        
        if not status:
            return jsonify({'error': 'Missing status'}), 400
        
        scanner.issue_manager.update_issue_status(issue_id, status, assignee)
        return jsonify({'success': True})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/rules')
def get_rules():
    """Get all security rules"""
    try:
        rules = {}
        for rule_id, rule in scanner.rules_engine.rules.items():
            rules[rule_id] = {
                'id': rule.id,
                'name': rule.name,
                'description': rule.description,
                'severity': rule.severity,
                'type': rule.type,
                'language': rule.language,
                'pattern': rule.pattern,
                'remediation_effort': rule.remediation_effort,
                'tags': rule.tags,
                'enabled': rule.enabled,
                'custom': rule.custom
            }
        
        return jsonify(rules)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/rules', methods=['POST'])
def create_rule():
    """Create a new security rule"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['id', 'name', 'description', 'severity', 'type', 'language', 'pattern']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Check if rule ID already exists
        if data['id'] in scanner.rules_engine.rules:
            return jsonify({'error': 'Rule ID already exists'}), 400
        
        # Create new rule
        rule = SecurityRule(
            id=data['id'],
            name=data['name'],
            description=data['description'],
            severity=data['severity'],
            type=data['type'],
            language=data['language'],
            pattern=data['pattern'],
            remediation_effort=data.get('remediation_effort', 30),
            tags=data.get('tags', []),
            enabled=data.get('enabled', True),
            custom=data.get('custom', True)
        )
        
        scanner.rules_engine.add_rule(rule)
        return jsonify({'success': True, 'rule_id': rule.id})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/rules/<rule_id>', methods=['PUT'])
def update_rule(rule_id):
    """Update a security rule"""
    try:
        data = request.get_json()
        
        if rule_id not in scanner.rules_engine.rules:
            return jsonify({'error': 'Rule not found'}), 404
        
        scanner.rules_engine.update_rule(rule_id, data)
        return jsonify({'success': True})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/rules/<rule_id>', methods=['DELETE'])
def delete_rule(rule_id):
    """Delete a security rule"""
    try:
        if rule_id not in scanner.rules_engine.rules:
            return jsonify({'error': 'Rule not found'}), 404
        
        scanner.rules_engine.delete_rule(rule_id)
        return jsonify({'success': True})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/quality-gates')
def get_quality_gates():
    """Get all quality gates"""
    try:
        gates = {}
        for gate_id, gate in scanner.quality_gates.gates.items():
            gates[gate_id] = {
                'id': gate.id,
                'name': gate.name,
                'conditions': gate.conditions,
                'is_default': gate.is_default
            }
        
        return jsonify(gates)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/quality-gates', methods=['POST'])
def create_quality_gate():
    """Create a new quality gate"""
    try:
        data = request.get_json()
        
        gate_id = str(uuid.uuid4())
        gate = QualityGate(
            id=gate_id,
            name=data['name'],
            conditions=data.get('conditions', []),
            is_default=data.get('is_default', False)
        )
        
        scanner.quality_gates.gates[gate_id] = gate
        scanner.quality_gates.save_gates()
        
        return jsonify({'success': True, 'gate_id': gate_id})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/quality-gates/<gate_id>', methods=['DELETE'])
def delete_quality_gate(gate_id):
    """Delete a quality gate"""
    try:
        if gate_id not in scanner.quality_gates.gates:
            return jsonify({'error': 'Quality gate not found'}), 404

        del scanner.quality_gates.gates[gate_id]
        scanner.quality_gates.save_gates()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    

@app.route('/api/scan-history')
def get_scan_history():
    """Get scan history"""
    try:
        history = []
        for scan in scanner.scan_history:
            history.append({
                'scan_id': scan.scan_id,
                'project_id': scan.project_id,
                'timestamp': scan.timestamp,
                'duration_ms': scan.duration_ms,
                'files_scanned': scan.files_scanned,
                'lines_of_code': scan.lines_of_code,
                'issues': len(scan.issues),
                'coverage': scan.coverage,
                'duplications': scan.duplications,
                'maintainability_rating': scan.maintainability_rating,
                'reliability_rating': scan.reliability_rating,
                'security_rating': scan.security_rating,
                'quality_gate_status': scan.quality_gate_status
            })
        
        # Sort by timestamp, newest first
        history.sort(key=lambda x: x['timestamp'], reverse=True)
        return jsonify(history)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/metrics/summary')
def get_metrics_summary():
    """Get summary metrics across all scans"""
    try:
        if not scanner.scan_history:
            return jsonify({'error': 'No scan data available'})
        
        latest_scan = max(scanner.scan_history, key=lambda x: x.timestamp)
        all_issues = []
        for scan in scanner.scan_history[-10:]:  # Last 10 scans
            all_issues.extend(scan.issues)
        
        # Calculate trend data
        trends = {
            'security_rating_trend': [],
            'issues_trend': [],
            'coverage_trend': []
        }
        
        for scan in scanner.scan_history[-10:]:
            trends['security_rating_trend'].append({
                'date': scan.timestamp,
                'value': ord(scan.security_rating) - ord('A') + 1
            })
            trends['issues_trend'].append({
                'date': scan.timestamp,
                'value': len(scan.issues)
            })
            trends['coverage_trend'].append({
                'date': scan.timestamp,
                'value': scan.coverage
            })
        
        summary = {
            'total_scans': len(scanner.scan_history),
            'total_projects': len(set(scan.project_id for scan in scanner.scan_history)),
            'total_issues': len(all_issues),
            'open_issues': len([i for i in all_issues if i.status == 'OPEN']),
            'resolved_issues': len([i for i in all_issues if i.status == 'RESOLVED']),
            'average_scan_duration': sum(scan.duration_ms for scan in scanner.scan_history) / len(scanner.scan_history),
            'latest_scan': {
                'project_id': latest_scan.project_id,
                'timestamp': latest_scan.timestamp,
                'security_rating': latest_scan.security_rating,
                'quality_gate_status': latest_scan.quality_gate_status
            },
            'trends': trends,
            'top_rules_violated': _get_top_rules_violated(all_issues),
            'issues_by_severity': _get_issues_by_severity(all_issues),
            'issues_by_type': _get_issues_by_type(all_issues)
        }
        
        return jsonify(summary)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def _get_top_rules_violated(issues):
    """Get top rules violated"""
    rule_counts = {}
    for issue in issues:
        rule_counts[issue.rule_id] = rule_counts.get(issue.rule_id, 0) + 1
    
    # Sort by count and return top 10
    sorted_rules = sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)
    return [{'rule_id': rule, 'count': count} for rule, count in sorted_rules[:10]]

def _get_issues_by_severity(issues):
    """Get issues grouped by severity"""
    severity_counts = {}
    for issue in issues:
        severity_counts[issue.severity] = severity_counts.get(issue.severity, 0) + 1
    return severity_counts

def _get_issues_by_type(issues):
    """Get issues grouped by type"""
    type_counts = {}
    for issue in issues:
        type_counts[issue.type] = type_counts.get(issue.type, 0) + 1
    return type_counts

@app.route('/api/leaderboard')
def get_leaderboard():
    """Get leaderboard of projects by security metrics"""
    try:
        projects = {}
        
        # Group scans by project and get latest scan for each
        for scan in scanner.scan_history:
            project_id = scan.project_id
            if project_id not in projects or scan.timestamp > projects[project_id]['timestamp']:
                projects[project_id] = {
                    'project_id': project_id,
                    'timestamp': scan.timestamp,
                    'security_rating': scan.security_rating,
                    'reliability_rating': scan.reliability_rating,
                    'maintainability_rating': scan.maintainability_rating,
                    'quality_gate_status': scan.quality_gate_status,
                    'total_issues': len(scan.issues),
                    'blocker_issues': len([i for i in scan.issues if i.severity == 'BLOCKER']),
                    'critical_issues': len([i for i in scan.issues if i.severity == 'CRITICAL']),
                    'coverage': scan.coverage,
                    'lines_of_code': scan.lines_of_code,
                    'technical_debt': MetricsCalculator.calculate_technical_debt(scan.issues)
                }
        
        # Calculate scores for ranking
        for project in projects.values():
            security_score = (ord('F') - ord(project['security_rating'])) * 20
            reliability_score = (ord('F') - ord(project['reliability_rating'])) * 20
            maintainability_score = (ord('F') - ord(project['maintainability_rating'])) * 20
            quality_gate_score = 50 if project['quality_gate_status'] == 'OK' else 0
            coverage_score = project['coverage']
            
            # Penalty for issues
            issue_penalty = project['blocker_issues'] * 10 + project['critical_issues'] * 5
            
            project['score'] = max(0, security_score + reliability_score + 
                                 maintainability_score + quality_gate_score + 
                                 coverage_score - issue_penalty)
        
        # Sort by score
        leaderboard = sorted(projects.values(), key=lambda x: x['score'], reverse=True)
        
        return jsonify(leaderboard)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/export')
def export_data():
    """Export all scanner data"""
    try:
        export_data = {
            'export_timestamp': datetime.now().isoformat(),
            'rules': [
                {
                    'id': rule.id,
                    'name': rule.name,
                    'description': rule.description,
                    'severity': rule.severity,
                    'type': rule.type,
                    'language': rule.language,
                    'pattern': rule.pattern,
                    'remediation_effort': rule.remediation_effort,
                    'tags': rule.tags,
                    'enabled': rule.enabled,
                    'custom': rule.custom
                }
                for rule in scanner.rules_engine.rules.values()
            ],
            'quality_gates': [
                {
                    'id': gate.id,
                    'name': gate.name,
                    'conditions': gate.conditions,
                    'is_default': gate.is_default
                }
                for gate in scanner.quality_gates.gates.values()
            ],
            'issues': [
                {
                    'id': issue.id,
                    'rule_id': issue.rule_id,
                    'file_path': issue.file_path,
                    'line_number': issue.line_number,
                    'column': issue.column,
                    'message': issue.message,
                    'severity': issue.severity,
                    'type': issue.type,
                    'status': issue.status,
                    'assignee': issue.assignee,
                    'creation_date': issue.creation_date,
                    'update_date': issue.update_date,
                    'effort': issue.effort,
                    'code_snippet': issue.code_snippet,
                    'suggested_fix': issue.suggested_fix
                }
                for issue in scanner.issue_manager.issues.values()
            ],
            'scan_history': [
                {
                    'scan_id': scan.scan_id,
                    'project_id': scan.project_id,
                    'timestamp': scan.timestamp,
                    'duration_ms': scan.duration_ms,
                    'files_scanned': scan.files_scanned,
                    'lines_of_code': scan.lines_of_code,
                    'coverage': scan.coverage,
                    'duplications': scan.duplications,
                    'maintainability_rating': scan.maintainability_rating,
                    'reliability_rating': scan.reliability_rating,
                    'security_rating': scan.security_rating,
                    'quality_gate_status': scan.quality_gate_status,
                    'issues_count': len(scan.issues)
                }
                for scan in scanner.scan_history
            ]
        }
        
        response = app.response_class(
            response=json.dumps(export_data, indent=2),
            status=200,
            mimetype='application/json'
        )
        response.headers['Content-Disposition'] = 'attachment; filename=security_scan_export.json'
        
        return response
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/import', methods=['POST'])
def import_data():
    """Import scanner data"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if not file.filename.endswith('.json'):
            return jsonify({'error': 'Invalid file format. JSON required'}), 400
        
        data = json.load(file)
        
        # Import rules
        if 'rules' in data:
            for rule_data in data['rules']:
                rule = SecurityRule(**rule_data)
                scanner.rules_engine.rules[rule.id] = rule
            scanner.rules_engine.save_rules()
        
        # Import quality gates
        if 'quality_gates' in data:
            for gate_data in data['quality_gates']:
                gate = QualityGate(**gate_data)
                scanner.quality_gates.gates[gate.id] = gate
            scanner.quality_gates.save_gates()
        
        # Import issues
        if 'issues' in data:
            for issue_data in data['issues']:
                issue = SecurityIssue(**issue_data)
                scanner.issue_manager.issues[issue.id] = issue
            scanner.issue_manager.save_issues()
        
        return jsonify({'success': True, 'message': 'Data imported successfully'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0',
        'scanner_status': 'operational',
        'data_directory': str(scanner.data_dir),
        'rules_count': len(scanner.rules_engine.rules),
        'quality_gates_count': len(scanner.quality_gates.gates),
        'total_issues': len(scanner.issue_manager.issues),
        'scan_history_count': len(scanner.scan_history)
    })

# @app.route('/api/scan/files', methods=['POST'])
# def scan_uploaded_files():
#     try:
#         data = request.get_json()
#         scan_id = data.get('scan_id', str(uuid.uuid4()))
#         scan_type = data.get('scan_type', 'quick')
#         file_contents = data.get('file_contents', [])
#         project_id = data.get('project_id', f'upload-scan-{int(datetime.now().timestamp())}')
#         project_name = data.get('project_name', 'File Upload Scan')
#         timestamp = datetime.utcnow().isoformat()

#         if not file_contents:
#             return jsonify({'error': 'No files provided'}), 400

#         issues = []
#         lines_of_code = 0
#         file_results = []

#         with tempfile.TemporaryDirectory() as temp_dir:
#             temp_path = Path(temp_dir)
#             for file_data in file_contents:
#                 file_path = temp_path / file_data['name']
#                 file_path.parent.mkdir(parents=True, exist_ok=True)

#                 with open(file_path, 'w', encoding='utf-8') as f:
#                     f.write(file_data['content'])

#                 content = file_data['content']
#                 lines = content.splitlines()
#                 loc = len(lines)
#                 lines_of_code += loc
#                 language = file_data['type']

#                 rules = scanner.rules_engine.get_enabled_rules(language)
#                 file_issues = scanner._scan_file_with_rules(file_data['name'], content, rules)
#                 issues.extend(file_issues)

#                 file_results.append({
#                     "file_id": file_data['id'],
#                     "file_name": file_data['name'],
#                     "file_type": language,
#                     "lines_scanned": loc,
#                     "issues_count": len(file_issues),
#                     "critical_issues": len([i for i in file_issues if i.severity == "CRITICAL"]),
#                     "issues": [asdict(i) for i in file_issues],
#                     "scan_status": "completed"
#                 })

#         # Metrics
#         coverage = 85.0
#         duplications = 2.0
#         tech_debt = MetricsCalculator.calculate_technical_debt(issues)
#         security_rating = MetricsCalculator.calculate_security_rating(issues)
#         reliability_rating = MetricsCalculator.calculate_reliability_rating(issues)
#         maintainability_rating = MetricsCalculator.calculate_maintainability_rating(tech_debt, lines_of_code)

#         metrics = {
#             "security_rating": ord(security_rating) - ord('A') + 1,
#             "reliability_rating": ord(reliability_rating) - ord('A') + 1,
#             "sqale_rating": ord(maintainability_rating) - ord('A') + 1,
#             "coverage": coverage,
#             "duplicated_lines_density": duplications,
#             "blocker_violations": len([i for i in issues if i.severity == "BLOCKER"]),
#             "critical_violations": len([i for i in issues if i.severity == "CRITICAL"])
#         }

#         default_gate = next((g for g in scanner.quality_gates.gates.values() if g.is_default), None)
#         gate_result = scanner.quality_gates.evaluate_gate(default_gate.id, metrics) if default_gate else {}
#         gate_status = gate_result.get("status", "OK")

#         # Save scan
#         scan_result = ScanResult(
#             project_id=project_id,
#             scan_id=scan_id,
#             timestamp=timestamp,
#             duration_ms=0,
#             files_scanned=len(file_contents),
#             lines_of_code=lines_of_code,
#             issues=issues,
#             coverage=coverage,
#             duplications=duplications,
#             maintainability_rating=maintainability_rating,
#             reliability_rating=reliability_rating,
#             security_rating=security_rating,
#             quality_gate_status=gate_status
#         )

#         scanner.scan_history.append(scan_result)
#         scanner.save_scan_history()
#         for issue in issues:
#             scanner.issue_manager.issues[issue.id] = issue
#         scanner.issue_manager.save_issues()

#         return jsonify({
#             "scan_id": scan_id,
#             "project_id": project_id,
#             "project_name": project_name,
#             "timestamp": timestamp,
#             "scan_type": scan_type,
#             "duration_ms": 0,
#             "files_scanned": len(file_contents),
#             "lines_of_code": lines_of_code,
#             "file_results": file_results,
#             "summary": {
#                 "total_issues": len(issues),
#                 "critical_issues": len([i for i in issues if i.severity == "CRITICAL"]),
#                 "quality_gate_passed": gate_status == "OK",
#                 "security_rating": security_rating,
#                 "technical_debt_hours": tech_debt // 60
#             },
#             "metrics": {
#                 "coverage": coverage,
#                 "duplications": duplications,
#                 "lines_of_code": lines_of_code,
#                 "maintainability_rating": maintainability_rating,
#                 "reliability_rating": reliability_rating,
#                 "security_rating": security_rating,
#                 "technical_debt_hours": tech_debt // 60
#             },
#             "quality_gate": {
#                 "status": gate_status,
#                 "message": "Quality Gate Passed" if gate_status == "OK" else "Quality Gate Failed"
#             },
#             "issue_breakdown": {
#                 "by_file": {f["file_name"]: f["issues_count"] for f in file_results},
#                 "by_severity": {},
#                 "by_type": {}
#             }
#         })

#     except Exception as e:
#         return jsonify({'error': str(e)}), 500

@app.route('/api/scan/files', methods=['POST'])
def scan_uploaded_files():
    try:
        data = request.get_json()
        scan_id = data.get('scan_id', str(uuid.uuid4()))
        scan_type = data.get('scan_type', 'quick')
        file_contents = data.get('file_contents', [])
        project_id = data.get('project_id', f'upload-scan-{int(datetime.now().timestamp())}')
        project_name = data.get('project_name', 'File Upload Scan')

        if not file_contents:
            return jsonify({'error': 'No files provided'}), 400

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            file_paths = []

            for file_data in file_contents:
                file_path = temp_path / file_data['name']
                file_path.parent.mkdir(parents=True, exist_ok=True)
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(file_data['content'])

                file_paths.append({
                    'id': file_data['id'],
                    'name': file_data['name'],
                    'path': str(file_path),
                    'type': file_data['type']
                })

            # ✅ Now delegate to your core scan function
            scan_result = perform_file_scan(
                scan_id=scan_id,
                project_id=project_id,
                project_name=project_name,
                file_paths=file_paths,
                scan_type=scan_type
            )

            return jsonify(scan_result)

    except Exception as e:
        return jsonify({'error': str(e)}), 500




def perform_file_scan(scan_id: str, project_id: str, project_name: str, 
                      file_paths: list, scan_type: str = 'quick') -> dict:
    """Perform security scan on uploaded files and persist results into scanner."""
    start_time = datetime.now()
    total_issues = []
    file_results = []
    total_lines = 0

    for file_info in file_paths:
        try:
            file_path = file_info['path']
            file_name = file_info['name']
            file_type = file_info['type']
            file_id = file_info['id']

            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            lines = content.splitlines()
            file_lines = len(lines)
            total_lines += file_lines

            applicable_rules = scanner.rules_engine.get_enabled_rules(file_type)
            file_issues = scan_file_content(file_name, content, applicable_rules, file_id)

            file_result = {
                'file_id': file_id,
                'file_name': file_name,
                'file_type': file_type,
                'lines_scanned': file_lines,
                'issues': [format_issue_for_response(issue) for issue in file_issues],
                'issues_count': len(file_issues),
                'critical_issues': len([i for i in file_issues if i.severity in ['BLOCKER', 'CRITICAL']]),
                'scan_status': 'completed'
            }

            file_results.append(file_result)
            total_issues.extend(file_issues)
        except Exception as e:
            file_results.append({
                'file_id': file_info['id'],
                'file_name': file_info['name'],
                'file_type': file_info['type'],
                'scan_status': 'error',
                'error_message': str(e)
            })

    # Compute metrics
    tech_debt = MetricsCalculator.calculate_technical_debt(total_issues)
    security_rating = MetricsCalculator.calculate_security_rating(total_issues)
    reliability_rating = MetricsCalculator.calculate_reliability_rating(total_issues)
    maintainability_rating = MetricsCalculator.calculate_maintainability_rating(tech_debt, total_lines)
    coverage = 85.0
    duplications = 2.0

    metrics = {
        'security_rating': ord(security_rating) - ord('A') + 1,
        'reliability_rating': ord(reliability_rating) - ord('A') + 1,
        'sqale_rating': ord(maintainability_rating) - ord('A') + 1,
        'coverage': coverage,
        'duplicated_lines_density': duplications,
        'blocker_violations': len([i for i in total_issues if i.severity == "BLOCKER"]),
        'critical_violations': len([i for i in total_issues if i.severity == "CRITICAL"])
    }

    default_gate = next((g for g in scanner.quality_gates.gates.values() if g.is_default), None)
    gate_result = scanner.quality_gates.evaluate_gate(default_gate.id, metrics) if default_gate else {}
    gate_status = gate_result.get("status", "OK")

    duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
    timestamp = start_time.isoformat()

    # Construct ScanResult
    scan_result_obj = ScanResult(
        project_id=project_id,
        scan_id=scan_id,
        timestamp=timestamp,
        duration_ms=duration_ms,
        files_scanned=len(file_paths),
        lines_of_code=total_lines,
        issues=total_issues,
        coverage=coverage,
        duplications=duplications,
        maintainability_rating=maintainability_rating,
        reliability_rating=reliability_rating,
        security_rating=security_rating,
        quality_gate_status=gate_status
    )

    # ✅ Save to scanner (history + issues)
    scanner.scan_history.append(scan_result_obj)
    scanner.save_scan_history()

    for issue in total_issues:
        scanner.issue_manager.issues[issue.id] = issue
    scanner.issue_manager.save_issues()

    # Return JSON-serializable response
    return {
        'scan_id': scan_id,
        'project_id': project_id,
        'project_name': project_name,
        'scan_type': scan_type,
        'timestamp': timestamp,
        'duration_ms': duration_ms,
        'files_scanned': len(file_paths),
        'lines_of_code': total_lines,
        'file_results': file_results,
        'summary': {
            'total_issues': len(total_issues),
            'critical_issues': len([i for i in total_issues if i.severity in ['BLOCKER', 'CRITICAL']]),
            'security_rating': security_rating,
            'quality_gate_passed': gate_status == "OK",
            'technical_debt_hours': tech_debt // 60
        },
        'metrics': {
            'coverage': coverage,
            'duplications': duplications,
            'lines_of_code': total_lines,
            'maintainability_rating': maintainability_rating,
            'reliability_rating': reliability_rating,
            'security_rating': security_rating,
            'technical_debt_hours': tech_debt // 60
        },
        'quality_gate': {
            'status': gate_status,
            'message': 'Quality Gate Passed' if gate_status == 'OK' else 'Quality Gate Failed'
        },
        'issue_breakdown': {
            'by_file': {f['file_name']: f['issues_count'] for f in file_results},
            'by_severity': {},  # Optionally populate
            'by_type': {}       # Optionally populate
        }
    }


def format_issue_for_response(issue) -> dict:
    """Format issue for JSON response"""
    return {
        'id': issue.id,
        'rule_id': issue.rule_id,
        'line_number': issue.line_number,
        'column': issue.column,
        'message': issue.message,
        'severity': issue.severity,
        'type': issue.type,
        'code_snippet': issue.code_snippet,
        'suggested_fix': issue.suggested_fix,
        'effort_minutes': getattr(issue, 'effort', 0)
    }

def scan_file_content(file_name: str, content: str, rules: list, file_id: str) -> list:
    """Scan file content with security rules"""
    import re
    issues = []
    lines = content.splitlines()

    for rule in rules:
        try:
            pattern = re.compile(rule.pattern, re.IGNORECASE | re.MULTILINE)

            for line_num, line in enumerate(lines, 1):
                matches = pattern.finditer(line)
                for match in matches:
                    issue = scanner.issue_manager.create_issue(
                        rule_id=rule.id,
                        file_path=file_name,
                        line_number=line_num,
                        column=match.start() + 1,
                        message=rule.description,
                        severity=rule.severity,
                        issue_type=rule.type,
                        code_snippet=line.strip(),
                        suggested_fix=generate_fix_suggestion(rule, line.strip())
                    )
                    issue.effort = rule.remediation_effort
                    issues.append(issue)

        except re.error as e:
            print(f"⚠️ Invalid regex in rule {rule.id}: {e}")

    return issues


def generate_fix_suggestion(rule, code_snippet: str) -> str:
    """Generate specific fix suggestions based on rule and code"""
    suggestions = {
        'python-hardcoded-secrets': f"Move the hardcoded value to environment variables: os.getenv('SECRET_KEY')",
        'python-sql-injection': "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
        'javascript-eval-usage': "Replace eval() with JSON.parse() for data or safer alternatives",
        'python-weak-crypto': "Replace with secure algorithms: hashlib.sha256() or hashlib.sha3_256()",
        'cross-lang-time-bomb': "Remove time-based logic or use proper scheduling systems"
    }
    
    base_suggestion = suggestions.get(rule.id, "Review and fix according to security best practices")
    
    # Add context-specific suggestions
    if 'password' in code_snippet.lower():
        return f"{base_suggestion}. Consider using secure password hashing with bcrypt or argon2."
    elif 'key' in code_snippet.lower():
        return f"{base_suggestion}. Use a secure key management service."
    elif 'token' in code_snippet.lower():
        return f"{base_suggestion}. Generate tokens securely and store them encrypted."
    
    return base_suggestion

@app.route('/api/scan/<scan_id>/export')
def export_scan_result(scan_id):
    try:
        scan_file = scanner.data_dir / f"scan_{scan_id}.json"
        if not scan_file.exists():
            return jsonify({'error': 'Scan result not found'}), 404
        return send_file(
            scan_file,
            as_attachment=True,
            download_name=f'security_scan_{scan_id}.json',
            mimetype='application/json'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan/<scan_id>/report')
def get_scan_report(scan_id):
    try:
        scan_file = scanner.data_dir / f"scan_{scan_id}.json"
        if not scan_file.exists():
            return jsonify({'error': 'Scan result not found'}), 404
        with open(scan_file, 'r') as f:
            scan_data = json.load(f)
        return generate_scan_report_html(scan_data), 200, {'Content-Type': 'text/html'}
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def generate_scan_report_html(scan_data: dict) -> str:
    """Generate comprehensive HTML report"""
    
    summary = scan_data['summary']
    metrics = scan_data['metrics']
    file_results = scan_data['file_results']
    
    # Calculate additional statistics
    total_files = len(file_results)
    files_with_issues = len([f for f in file_results if f.get('issues_count', 0) > 0])
    
    report_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Security Scan Report - {scan_data['project_name']}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 8px; }}
            .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
            .metric {{ background: #f8f9fa; padding: 15px; border-radius: 8px; text-align: center; }}
            .metric-value {{ font-size: 2rem; font-weight: bold; margin-bottom: 5px; }}
            .metric-label {{ color: #666; font-size: 0.9rem; }}
            .section {{ margin: 30px 0; }}
            .file-item {{ background: white; border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 8px; }}
            .issue {{ background: #fff3cd; border-left: 4px solid #ffc107; padding: 10px; margin: 5px 0; }}
            .issue.critical {{ border-left-color: #dc3545; background: #f8d7da; }}
            .issue.major {{ border-left-color: #fd7e14; background: #fff3cd; }}
            .severity {{ padding: 2px 8px; border-radius: 12px; font-size: 0.8rem; font-weight: bold; }}
            .severity-CRITICAL {{ background: #dc3545; color: white; }}
            .severity-MAJOR {{ background: #fd7e14; color: white; }}
            .severity-MINOR {{ background: #17a2b8; color: white; }}
            .code {{ background: #f8f9fa; padding: 5px; border-radius: 4px; font-family: monospace; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Security Scan Report</h1>
            <p>Project: {scan_data['project_name']}</p>
            <p>Scan ID: {scan_data['scan_id']}</p>
            <p>Date: {datetime.fromisoformat(scan_data['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="summary">
            <div class="metric">
                <div class="metric-value">{summary['total_issues']}</div>
                <div class="metric-label">Total Issues</div>
            </div>
            <div class="metric">
                <div class="metric-value">{summary['critical_issues']}</div>
                <div class="metric-label">Critical Issues</div>
            </div>
            <div class="metric">
                <div class="metric-value">{metrics['security_rating']}</div>
                <div class="metric-label">Security Rating</div>
            </div>
            <div class="metric">
                <div class="metric-value">{'PASSED' if summary['quality_gate_passed'] else 'FAILED'}</div>
                <div class="metric-label">Quality Gate</div>
            </div>
            <div class="metric">
                <div class="metric-value">{total_files}</div>
                <div class="metric-label">Files Scanned</div>
            </div>
            <div class="metric">
                <div class="metric-value">{files_with_issues}</div>
                <div class="metric-label">Files with Issues</div>
            </div>
        </div>
        
        <div class="section">
            <h2>File Analysis Results</h2>
    """
    
    for file_result in file_results:
        issues_count = file_result.get('issues_count', 0)
        file_html = f"""
            <div class="file-item">
                <h3>{file_result['file_name']} ({file_result['file_type']})</h3>
                <p>Lines scanned: {file_result.get('lines_scanned', 0)} | Issues found: {issues_count}</p>
        """
        
        if issues_count > 0:
            file_html += "<div style='margin-top: 15px;'>"
            for issue in file_result.get('issues', []):
                severity_class = issue['severity'].lower()
                file_html += f"""
                    <div class="issue {severity_class}">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <strong>Line {issue['line_number']}: {issue['message']}</strong>
                            <span class="severity severity-{issue['severity']}">{issue['severity']}</span>
                        </div>
                        <div class="code">{issue['code_snippet']}</div>
                        <div style="margin-top: 8px; color: #28a745;">
                            <strong>Fix:</strong> {issue['suggested_fix']}
                        </div>
                    </div>
                """
            file_html += "</div>"
        else:
            file_html += "<div style='color: #28a745; font-weight: bold;'>✓ No security issues found</div>"
        
        file_html += "</div>"
        report_html += file_html
    
    report_html += """
        </div>
        
        <div class="section">
            <h2>Scan Summary</h2>
            <p>This security scan analyzed your uploaded files for common vulnerabilities and code quality issues.</p>
            <p>For critical and major issues, please review the suggested fixes and implement them as soon as possible.</p>
            <p>Generated by Enhanced Security Scanner on """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</p>
        </div>
    </body>
    </html>
    """
    
    return report_html

@app.route('/api/scan/history')
def get_file_scan_history():
    try:
        scan_history_file = scanner.data_dir / "file_scan_history.json"
        if not scan_history_file.exists():
            return jsonify([])
        with open(scan_history_file, 'r') as f:
            history = json.load(f)
        history.sort(key=lambda x: x['timestamp'], reverse=True)
        return jsonify(history)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/files/supported-types')
def get_supported_file_types():
    return jsonify({
        'extensions': [
            '.py', '.js', '.ts', '.java', '.html', '.css', '.json',
            '.xml', '.sql', '.rb', '.go', '.c', '.cpp', '.cs'
        ],
        'max_file_size_mb': 16,
        'max_files_per_upload': 50
    })


@app.route('/api/dashboard/file-upload-metrics')
def get_file_upload_metrics():
    try:
        scan_history_file = scanner.data_dir / "file_scan_history.json"
        if not scan_history_file.exists():
            return jsonify({'error': 'No file upload history found'})
        with open(scan_history_file, 'r') as f:
            history = json.load(f)
        if not history:
            return jsonify({'error': 'No scans found'})
        recent = history[-10:]
        return jsonify({
            'latest_scan': recent[-1],
            'recent_activity': {
                'total_scans': len(recent),
                'total_files_scanned': sum(s['files_scanned'] for s in recent),
                'total_issues_found': sum(s['total_issues'] for s in recent),
                'quality_gate_pass_rate': 100 * sum(1 for s in recent if s['quality_gate_passed']) / len(recent),
                'average_issues_per_scan': sum(s['total_issues'] for s in recent) / len(recent)
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("🚀 Starting Enhanced Security Scanner Dashboard...")
    print("📊 SonarQube-equivalent features enabled:")
    print("  • Project Overview & Metrics")
    print("  • Security Rules Management")
    print("  • Quality Gates Configuration")
    print("  • Issue Tracking & Workflow")
    print("  • Scan Activity & History")
    print("  • Leaderboard & Rankings")
    print("  • Data Export/Import")
    print("  • Real-time Dashboard")
    print("\n🌐 Dashboard available at: http://localhost:5000")
    print("📋 API endpoints:")
    print("  • GET  /api/dashboard/metrics - Dashboard data")
    print("  • POST /api/scan - Start new scan")
    print("  • GET  /api/issues - List all issues")
    print("  • GET  /api/rules - Manage security rules")
    print("  • GET  /api/quality-gates - Quality gate management")
    print("  • GET  /api/leaderboard - Project rankings")
    print("  • GET  /api/export - Export all data")
    print("="*80)
    
    app.run(host='127.0.0.1', port=5000, debug=True)