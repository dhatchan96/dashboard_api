#!/usr/bin/env python3
"""
ThreatGuard Pro - Command Center Dashboard API
Advanced Logic Bomb Detection & Threat Intelligence Dashboard
Copyright 2025 - Specialized in Logic Bomb & Trigger-Based Threat Detection
"""

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import json
import os
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import uuid
import tempfile
from pathlib import Path
import io
import zipfile
from dataclasses import dataclass

# Import our main logic bomb detector components
from threatguard_main import (
    LogicBombDetector, SecurityRule, ThreatShield, SecurityIssue,
    ThreatMetricsCalculator, ScanResult
)

app = Flask(__name__)
CORS(app)

# Initialize logic bomb detector
detector = LogicBombDetector()

@dataclass
class LogicBombPattern:
    """Advanced logic bomb pattern for multi-language detection."""
    pattern_type: str
    description: str
    severity: str
    line_number: int
    code_snippet: str
    confidence: float
    language: str
    trigger_analysis: str = ""
    payload_analysis: str = ""

class AdvancedLogicBombDetector:
    def __init__(self):
        self.logic_bomb_patterns = []
        self.supported_languages = {
            '.py': 'python', '.java': 'java', '.js': 'javascript', '.ts': 'typescript',
            '.cs': 'csharp', '.vb': 'vbnet', '.jsx': 'react', '.tsx': 'react_typescript',
            '.json': 'config', '.html': 'html', '.php': 'php', '.rb': 'ruby',
            '.go': 'golang', '.cpp': 'cpp', '.c': 'c', '.rs': 'rust'
        }
        self.init_logic_bomb_signatures()

    def init_logic_bomb_signatures(self):
        """Initialize comprehensive logic bomb signatures"""
        # Time-based logic bombs
        self.time_bomb_patterns = [
            (r'if.*(?:date|datetime|time).*[><=].*\d{4}.*:.*(?:delete|remove|destroy|format)', "Date-based trigger"),
            (r'(?:datetime\.now|time\.time|Date\.now)\(\).*[><=].*\d+.*:.*(?:rm|del|unlink)', "Time comparison trigger"),
            (r'if.*(?:month|day|year).*==.*\d+.*:.*(?:format|rmdir|system)', "Calendar-based trigger")
        ]
        
        # User-targeted logic bombs  
        self.user_bomb_patterns = [
            (r'if.*(?:getuser|username|user|USER).*==.*["\'][^"\']+["\'].*:.*(?:delete|corrupt|destroy)', "User-specific trigger"),
            (r'if.*os\.environ\[["\'](?:USER|USERNAME)["\'].*==.*:.*(?:subprocess|system|exec)', "Environment user check"),
            (r'if.*whoami.*==.*["\'][^"\']+["\'].*:.*(?:rm|del|kill)', "Identity-based trigger")
        ]
        
        # Counter-based logic bombs
        self.counter_bomb_patterns = [
            (r'(?:count|counter|iteration|exec_count)\s*[><=]\s*\d+.*:.*(?:delete|remove|destroy)', "Execution counter"),
            (r'if.*(?:attempts|tries|loops).*==.*\d+.*:.*(?:format|corrupt|terminate)', "Attempt-based trigger"),
            (r'for.*range\(\d+\).*:.*(?:break|exit).*(?:delete|remove)', "Loop-based trigger")
        ]
        
        # Environment-based logic bombs
        self.environment_bomb_patterns = [
            (r'if.*(?:hostname|platform|gethostname).*==.*["\'][^"\']*["\'].*:.*(?:sys\.|os\.|subprocess)', "System-specific trigger"),
            (r'if.*(?:env|environment).*!=.*["\'][^"\']*["\'].*:.*(?:destroy|corrupt)', "Environment mismatch trigger"),
            (r'if.*socket\.gethostname.*==.*["\'][^"\']*["\'].*:.*(?:system|exec)', "Network hostname trigger")
        ]
        
        # Destructive payload detection
        self.payload_patterns = [
            (r'(?:shutil\.rmtree|os\.remove|subprocess\.call.*rm|system.*(?:del|rm)|rmdir.*\/s)', "File destruction"),
            (r'(?:format.*c:|mkfs|fdisk|dd.*if=)', "Disk formatting/destruction"),
            (r'(?:kill.*-9|taskkill.*\/f|killall|pkill)', "Process termination"),
            (r'(?:DROP\s+TABLE|TRUNCATE\s+TABLE|DELETE\s+FROM.*WHERE.*1=1)', "Database destruction")
        ]
        
        # Network-based triggers
        self.network_bomb_patterns = [
            (r'if.*(?:ping|connect|socket|urllib).*(?:fail|error|timeout).*:.*(?:delete|remove|destroy)', "Network failure trigger"),
            (r'if.*(?:requests\.get|urllib\.request).*(?:status_code|response).*!=.*200.*:.*(?:corrupt|delete)', "HTTP status trigger"),
            (r'if.*(?:socket\.connect|telnet|ssh).*(?:refused|timeout).*:.*(?:system|exec)', "Connection failure trigger")
        ]

    def detect_language(self, filepath: str, content: str) -> str:
        _, ext = os.path.splitext(filepath.lower())
        return self.supported_languages.get(ext, 'unknown')

    def analyze_file(self, filepath: str) -> list:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            language = self.detect_language(filepath, content)
            self.logic_bomb_patterns = []
            self._check_all_patterns(content, language, filepath)
            return self.logic_bomb_patterns
        except Exception:
            return []

    def _check_all_patterns(self, content: str, language: str, filepath: str):
        lines = content.split('\n')
        
        pattern_groups = [
            (self.time_bomb_patterns, "SCHEDULED_THREAT"),
            (self.user_bomb_patterns, "TARGETED_ATTACK"), 
            (self.counter_bomb_patterns, "EXECUTION_TRIGGER"),
            (self.environment_bomb_patterns, "SYSTEM_SPECIFIC_THREAT"),
            (self.payload_patterns, "DESTRUCTIVE_PAYLOAD"),
            (self.network_bomb_patterns, "CONNECTION_BASED_THREAT")
        ]
        
        for pattern_list, bomb_type in pattern_groups:
            for pattern, desc in pattern_list:
                for i, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        # Analyze trigger and payload
                        trigger_analysis = self._analyze_trigger_condition(line, bomb_type)
                        payload_analysis = self._analyze_payload_potential(line, bomb_type)
                        
                        # Determine severity based on bomb type and payload
                        severity = self._determine_severity(bomb_type, line)
                        confidence = self._calculate_confidence(line, bomb_type, pattern)
                        
                        self.logic_bomb_patterns.append(
                            LogicBombPattern(
                                bomb_type, desc, severity, i, line.strip(), 
                                confidence, language, trigger_analysis, payload_analysis
                            )
                        )

    def _analyze_trigger_condition(self, line: str, bomb_type: str) -> str:
        """Analyze what triggers this logic bomb"""
        if bomb_type == "SCHEDULED_THREAT":
            if re.search(r'\d{4}', line):
                return f"Triggered on specific year: {re.search(r'\d{4}', line).group()}"
            elif "datetime" in line or "time" in line:
                return "Triggered by time-based condition"
        elif bomb_type == "TARGETED_ATTACK":
            user_match = re.search(r'["\']([^"\']+)["\']', line)
            if user_match:
                return f"Triggered for user: {user_match.group(1)}"
        elif bomb_type == "EXECUTION_TRIGGER":
            count_match = re.search(r'\d+', line)
            if count_match:
                return f"Triggered after {count_match.group()} executions"
        elif bomb_type == "SYSTEM_SPECIFIC_THREAT":
            env_match = re.search(r'["\']([^"\']+)["\']', line)
            if env_match:
                return f"Triggered on system: {env_match.group(1)}"
        return f"Conditional trigger detected for {bomb_type}"

    def _analyze_payload_potential(self, line: str, bomb_type: str) -> str:
        """Analyze potential damage from this logic bomb"""
        destructive_keywords = {
            "delete": "File deletion - Data loss",
            "remove": "Data removal - Information loss", 
            "destroy": "Data destruction - Complete loss",
            "format": "System formatting - Total destruction",
            "kill": "Process termination - Service disruption",
            "corrupt": "Data corruption - Integrity loss",
            "truncate": "Database truncation - Data wipe",
            "drop": "Database destruction - Schema loss"
        }
        
        for keyword, description in destructive_keywords.items():
            if keyword in line.lower():
                return description
        
        return f"Potential {bomb_type} payload detected"

    def _determine_severity(self, bomb_type: str, line: str) -> str:
        """Determine severity based on bomb type and payload"""
        if bomb_type == "DESTRUCTIVE_PAYLOAD":
            return "CRITICAL_BOMB"
        elif "format" in line.lower() or "destroy" in line.lower():
            return "CRITICAL_BOMB"
        elif bomb_type in ["SCHEDULED_THREAT", "TARGETED_ATTACK"]:
            return "HIGH_RISK"
        elif bomb_type == "EXECUTION_TRIGGER":
            return "MEDIUM_RISK"
        else:
            return "LOW_RISK"

    def _calculate_confidence(self, line: str, bomb_type: str, pattern: str) -> float:
        """Calculate confidence score for detection"""
        base_confidence = 0.7
        
        # Increase confidence for specific indicators
        if bomb_type == "DESTRUCTIVE_PAYLOAD":
            base_confidence += 0.2
        if re.search(r'if.*:.*(?:delete|remove|destroy)', line):
            base_confidence += 0.1
        if len(re.findall(r'(?:delete|remove|destroy|corrupt|kill)', line, re.IGNORECASE)) > 1:
            base_confidence += 0.1
            
        return min(1.0, base_confidence)

# Global advanced logic bomb detector instance
advanced_detector = AdvancedLogicBombDetector()

@app.route('/api/command-center/metrics')
def get_command_center_metrics():
    """Get command center metrics (replaces dashboard metrics)"""
    try:
        metrics = detector.get_command_center_metrics()

        # Add recent threats to the response
        if not metrics.get('error'):
            recent_threats = []
            logic_bomb_issues = []

            for scan in detector.scan_history[-5:]:  # Last 5 scans
                for issue in scan.issues[:10]:  # Top 10 issues per scan
                    threat_data = {
                        'id': issue.id,
                        'rule_id': issue.rule_id,
                        'file_path': issue.file_path,
                        'line_number': issue.line_number,
                        'message': issue.message,
                        'severity': issue.severity,
                        'type': issue.type,
                        'status': issue.status,
                        'suggested_fix': issue.suggested_fix,
                        'trigger_analysis': getattr(issue, 'trigger_analysis', ''),
                        'payload_analysis': getattr(issue, 'payload_analysis', ''),
                        'threat_level': getattr(issue, 'threat_level', 'UNKNOWN')
                    }
                    recent_threats.append(threat_data)

                    if issue.type in ["SCHEDULED_THREAT", "TARGETED_ATTACK", "EXECUTION_TRIGGER", "DESTRUCTIVE_PAYLOAD"]:
                        logic_bomb_issues.append(issue)

            metrics['recent_threats'] = recent_threats[-20:]

            # Add logic bomb-specific analytics
            if logic_bomb_issues:
                metrics['logic_bomb_analysis'] = {
                    'by_type': {
                        bomb_type: sum(1 for i in logic_bomb_issues if i.type == bomb_type)
                        for bomb_type in set(i.type for i in logic_bomb_issues)
                    },
                    'by_severity': {
                        'CRITICAL_BOMB': sum(1 for i in logic_bomb_issues if i.severity == "CRITICAL_BOMB"),
                        'HIGH_RISK': sum(1 for i in logic_bomb_issues if i.severity == "HIGH_RISK"),
                        'MEDIUM_RISK': sum(1 for i in logic_bomb_issues if i.severity == "MEDIUM_RISK")
                    }
                }

        return jsonify(metrics)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/logic-bomb-scan', methods=['POST'])
def start_logic_bomb_scan():
    """Start a new logic bomb detection scan"""
    try:
        data = request.get_json()
        project_path = data.get('project_path')
        project_id = data.get('project_id')
        
        if not project_path or not project_id:
            return jsonify({'error': 'Missing project_path or project_id'}), 400
        
        if not os.path.exists(project_path):
            return jsonify({'error': 'Project path does not exist'}), 400
        
        # Start logic bomb scan
        result = detector.scan_project(project_path, project_id)
        
        return jsonify({
            'scan_id': result.scan_id,
            'project_id': result.project_id,
            'timestamp': result.timestamp,
            'files_scanned': result.files_scanned,
            'logic_bombs_detected': len(result.issues),
            'duration_ms': result.duration_ms,
            'threat_shield_status': result.threat_shield_status,
            'logic_bomb_risk_score': result.logic_bomb_risk_score,
            'threat_level': result.threat_intelligence.get('threat_level', 'UNKNOWN')
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/threats')
def get_threats():
    """Get all logic bomb threats"""
    try:
        threats = []
        for issue in detector.issue_manager.issues.values():
            threats.append({
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
                'suggested_fix': issue.suggested_fix,
                'threat_level': getattr(issue, 'threat_level', 'UNKNOWN'),
                'trigger_analysis': getattr(issue, 'trigger_analysis', ''),
                'payload_analysis': getattr(issue, 'payload_analysis', '')
            })
        
        return jsonify(threats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/threats/<threat_id>/status', methods=['PUT'])
def update_threat_status(threat_id):
    """Update threat status"""
    try:
        data = request.get_json()
        status = data.get('status')
        assignee = data.get('assignee')
        
        if not status:
            return jsonify({'error': 'Missing status'}), 400
        
        detector.issue_manager.update_issue_status(threat_id, status, assignee)
        return jsonify({'success': True})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/threats/<threat_id>/neutralize', methods=['POST'])
def neutralize_threat(threat_id):
    """Neutralize a specific threat"""
    try:
        detector.issue_manager.update_issue_status(threat_id, "NEUTRALIZED")
        return jsonify({'success': True, 'message': 'Threat neutralized'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/threat-shields')
def get_threat_shields():
    """Get all threat shields"""
    try:
        shields = {}
        for shield_id, shield in detector.threat_shields.shields.items():
            shields[shield_id] = {
                'id': shield.id,
                'name': shield.name,
                'protection_rules': shield.protection_rules,
                'is_default': shield.is_default,
                'threat_categories': shield.threat_categories,
                'risk_threshold': shield.risk_threshold
            }
        
        return jsonify(shields)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/threat-shields', methods=['POST'])
def create_threat_shield():
    """Create a new threat shield"""
    try:
        data = request.get_json()
        
        shield_id = str(uuid.uuid4())
        shield = ThreatShield(
            id=shield_id,
            name=data['name'],
            protection_rules=data.get('protection_rules', []),
            is_default=data.get('is_default', False),
            threat_categories=data.get('threat_categories', []),
            risk_threshold=data.get('risk_threshold', 'MEDIUM_RISK')
        )
        
        detector.threat_shields.shields[shield_id] = shield
        detector.threat_shields.save_shields()
        
        return jsonify({'success': True, 'shield_id': shield_id})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/threat-intelligence')
def get_threat_intelligence():
    """Get threat intelligence data"""
    try:
        history = []
        for scan in detector.scan_history:
            history.append({
                'scan_id': scan.scan_id,
                'project_id': scan.project_id,
                'timestamp': scan.timestamp,
                'duration_ms': scan.duration_ms,
                'files_scanned': scan.files_scanned,
                'logic_bombs': len(scan.issues),
                'logic_bomb_risk_score': getattr(scan, 'logic_bomb_risk_score', 0),
                'threat_shield_status': scan.threat_shield_status,
                'threat_level': scan.threat_intelligence.get('threat_level', 'UNKNOWN') if scan.threat_intelligence else 'UNKNOWN'
            })
        
        # Sort by timestamp, newest first
        history.sort(key=lambda x: x['timestamp'], reverse=True)
        
        # Calculate intelligence stats
        total_scans = len(history)
        threats_neutralized = len([i for i in detector.issue_manager.issues.values() if i.status == "NEUTRALIZED"])
        avg_risk_score = sum(h.get('logic_bomb_risk_score', 0) for h in history) / max(1, total_scans)
        shield_effectiveness = len([h for h in history if h['threat_shield_status'] == 'PROTECTED']) / max(1, total_scans) * 100
        
        return jsonify({
            'scan_history': history,
            'total_scans': total_scans,
            'threats_neutralized': threats_neutralized,
            'avg_risk_score': round(avg_risk_score, 1),
            'shield_effectiveness': round(shield_effectiveness, 1)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/files', methods=['POST'])
def scan_uploaded_files():
    try:
        data = request.get_json()
        scan_id = data.get('scan_id', str(uuid.uuid4()))
        scan_type = data.get('scan_type', 'quick')
        file_contents = data.get('file_contents', [])
        project_id = data.get('project_id', f'logic-bomb-scan-{int(datetime.now().timestamp())}')
        project_name = data.get('project_name', 'Logic Bomb Detection Scan')

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

            # Delegate to logic bomb scan function
            scan_result = perform_logic_bomb_file_scan(
                scan_id=scan_id,
                project_id=project_id,
                project_name=project_name,
                file_paths=file_paths,
                scan_type=scan_type
            )

            return jsonify(scan_result)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

def perform_logic_bomb_file_scan(scan_id: str, project_id: str, project_name: str, 
                                file_paths: list, scan_type: str = 'quick') -> dict:
    """Perform logic bomb scan on uploaded files"""
    start_time = datetime.now()
    total_issues = []
    total_logic_bomb_patterns = []
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

            # Standard logic bomb rules
            applicable_rules = detector.rules_engine.get_enabled_rules(file_type)
            file_issues = scan_file_content(file_name, content, applicable_rules, file_id)

            # Advanced logic bomb detection
            logic_bomb_matches = advanced_detector.analyze_file(file_path)
            logic_bomb_issues = [
                detector.issue_manager.create_issue(
                    rule_id=f"LOGIC_BOMB_{pattern.pattern_type}",
                    file_path=file_name,
                    line_number=pattern.line_number,
                    column=1,
                    message=pattern.description,
                    severity=pattern.severity,
                    issue_type=pattern.pattern_type,
                    code_snippet=pattern.code_snippet,
                    suggested_fix=f"URGENT: {pattern.pattern_type.replace('_', ' ').title()} detected - {pattern.payload_analysis}"
                )
                for pattern in logic_bomb_matches
            ]

            # Set additional threat analysis
            for issue, pattern in zip(logic_bomb_issues, logic_bomb_matches):
                issue.trigger_analysis = pattern.trigger_analysis
                issue.payload_analysis = pattern.payload_analysis
                issue.threat_level = "EXTREME" if pattern.severity == "CRITICAL_BOMB" else "HIGH"

            all_issues = file_issues + logic_bomb_issues

            file_result = {
                'file_id': file_id,
                'file_name': file_name,
                'file_type': file_type,
                'lines_scanned': file_lines,
                'issues': [format_issue_for_response(issue) for issue in all_issues],
                'issues_count': len(all_issues),
                'logic_bomb_count': len(logic_bomb_matches),
                'critical_threats': len([i for i in all_issues if i.severity in ['CRITICAL_BOMB', 'HIGH_RISK']]),
                'scan_status': 'completed'
            }

            file_results.append(file_result)
            total_issues.extend(all_issues)
            total_logic_bomb_patterns.extend(logic_bomb_matches)

        except Exception as e:
            file_results.append({
                'file_id': file_info['id'],
                'file_name': file_info['name'],
                'file_type': file_info['type'],
                'scan_status': 'error',
                'error_message': str(e)
            })

    # Compute specialized threat metrics
    logic_bomb_risk_score = ThreatMetricsCalculator.calculate_logic_bomb_risk_score(total_issues)
    threat_intelligence = ThreatMetricsCalculator.calculate_threat_intelligence(total_issues)
    
    # Standard ratings (simplified for logic bomb focus)
    security_rating = detector._calculate_security_rating(total_issues)
    reliability_rating = "A"
    maintainability_rating = "B"
    
    # Evaluate threat shield
    threat_metrics = {
        "SCHEDULED_THREAT": len([i for i in total_issues if i.type == "SCHEDULED_THREAT"]),
        "TARGETED_ATTACK": len([i for i in total_issues if i.type == "TARGETED_ATTACK"]), 
        "EXECUTION_TRIGGER": len([i for i in total_issues if i.type == "EXECUTION_TRIGGER"]),
        "DESTRUCTIVE_PAYLOAD": len([i for i in total_issues if i.type == "DESTRUCTIVE_PAYLOAD"]),
        "LOGIC_BOMB": len([i for i in total_issues if "LOGIC_BOMB" in i.type])
    }

    default_shield = next((s for s in detector.threat_shields.shields.values() if s.is_default), None)
    shield_result = detector.threat_shields.evaluate_shield(default_shield.id, threat_metrics) if default_shield else {}
    shield_status = shield_result.get("status", "UNPROTECTED")

    duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
    timestamp = start_time.isoformat()

    # Construct ScanResult with threat intelligence
    scan_result_obj = ScanResult(
        project_id=project_id,
        scan_id=scan_id,
        timestamp=timestamp,
        duration_ms=duration_ms,
        files_scanned=len(file_paths),
        lines_of_code=total_lines,
        issues=total_issues,
        coverage=85.0,
        duplications=2.0,
        maintainability_rating=maintainability_rating,
        reliability_rating=reliability_rating,
        security_rating=security_rating,
        threat_shield_status=shield_status,
        logic_bomb_risk_score=logic_bomb_risk_score,
        threat_intelligence=threat_intelligence
    )

    # Save to detector
    detector.scan_history.append(scan_result_obj)
    detector.save_scan_history()

    for issue in total_issues:
        detector.issue_manager.issues[issue.id] = issue
    detector.issue_manager.save_issues()

    # Save threat analysis prompts
    threat_output_dir = detector.data_dir / "threat_prompts"
    export_threat_prompts(total_issues, threat_output_dir)

    return {
        'scan_id': scan_id,
        'project_id': project_id,
        'project_name': project_name,
        'scan_type': scan_type,
        'timestamp': timestamp,
        'scan_date': datetime.fromisoformat(timestamp).strftime('%Y-%m-%d'),
        'scan_time': datetime.fromisoformat(timestamp).strftime('%H:%M:%S'),
        'duration_ms': duration_ms,
        'files_scanned': len(file_paths),
        'lines_of_code': total_lines,
        'file_results': file_results,
        'summary': {
            'total_threats': len(total_issues),
            'logic_bomb_patterns_found': len(total_logic_bomb_patterns),
            'critical_threats': len([i for i in total_issues if i.severity in ['CRITICAL_BOMB', 'HIGH_RISK']]),
            'logic_bomb_risk_score': logic_bomb_risk_score,
            'threat_level': threat_intelligence.get('threat_level', 'UNKNOWN'),
            'threat_shield_passed': shield_status in ["PROTECTED", "OK"],
            'neutralization_urgency_hours': sum(issue.effort for issue in total_issues) // 60
        },
        'logic_bomb_metrics': {
            'logic_bomb_risk_score': logic_bomb_risk_score,
            'threat_exposure_level': threat_intelligence.get('threat_level', 'MINIMAL'),
            'time_bomb_count': len([p for p in total_logic_bomb_patterns if p.pattern_type == 'SCHEDULED_THREAT']),
            'user_bomb_count': len([p for p in total_logic_bomb_patterns if p.pattern_type == 'TARGETED_ATTACK']),
            'counter_bomb_count': len([p for p in total_logic_bomb_patterns if p.pattern_type == 'EXECUTION_TRIGGER']),
            'destructive_payload_count': len([p for p in total_logic_bomb_patterns if p.pattern_type == 'DESTRUCTIVE_PAYLOAD']),
            'environment_bomb_count': len([p for p in total_logic_bomb_patterns if p.pattern_type == 'SYSTEM_SPECIFIC_THREAT']),
            'network_bomb_count': len([p for p in total_logic_bomb_patterns if p.pattern_type == 'CONNECTION_BASED_THREAT']),
            'trigger_complexity_score': calculate_trigger_complexity(total_logic_bomb_patterns),
            'payload_severity_score': calculate_payload_severity(total_logic_bomb_patterns),
            'neutralization_urgency_hours': sum(issue.effort for issue in total_issues) // 60,
            'threat_density': len(total_logic_bomb_patterns) / max(1, total_lines) * 1000,  # threats per 1K lines
            'detection_confidence_avg': sum(p.confidence for p in total_logic_bomb_patterns) / max(1, len(total_logic_bomb_patterns)),
            'files_with_logic_bombs': len(set(p.pattern_type for p in total_logic_bomb_patterns)),
            'critical_bomb_ratio': len([p for p in total_logic_bomb_patterns if p.severity == 'CRITICAL_BOMB']) / max(1, len(total_logic_bomb_patterns)) * 100
        },
        'threat_shield': {
            'status': shield_status,
            'message': 'Threat Shield Active' if shield_status == 'PROTECTED' else 'Threat Shield Alert',
            'protection_effectiveness': calculate_shield_effectiveness(shield_status, total_logic_bomb_patterns),
            'blocked_patterns': len([p for p in total_logic_bomb_patterns if p.severity == 'CRITICAL_BOMB']) if shield_status == 'BLOCKED' else 0
        },
        'threat_analysis': {
            'total_patterns': len(total_logic_bomb_patterns),
            'by_severity': {
                'CRITICAL_BOMB': len([p for p in total_logic_bomb_patterns if p.severity == 'CRITICAL_BOMB']),
                'HIGH_RISK': len([p for p in total_logic_bomb_patterns if p.severity == 'HIGH_RISK']),
                'MEDIUM_RISK': len([p for p in total_logic_bomb_patterns if p.severity == 'MEDIUM_RISK'])
            },
            'by_type': {
                pattern_type: len([p for p in total_logic_bomb_patterns if p.pattern_type == pattern_type])
                for pattern_type in set(p.pattern_type for p in total_logic_bomb_patterns)
            },
            'threat_intelligence': threat_intelligence,
            'most_dangerous_patterns': get_most_dangerous_patterns(total_logic_bomb_patterns),
            'recommended_actions': generate_action_recommendations(total_logic_bomb_patterns, threat_intelligence)
        }
    }

def calculate_trigger_complexity(patterns: list) -> float:
    """Calculate complexity score of trigger mechanisms (0-100)"""
    if not patterns:
        return 0.0
    
    complexity_weights = {
        'SCHEDULED_THREAT': 8.0,      # Time-based triggers are complex
        'TARGETED_ATTACK': 7.0,      # User-targeted attacks are sophisticated
        'EXECUTION_TRIGGER': 6.0,   # Counter-based triggers are moderately complex
        'SYSTEM_SPECIFIC_THREAT': 5.0, # Environment checks are somewhat complex
        'DESTRUCTIVE_PAYLOAD': 9.0, # Direct destruction is highly dangerous
        'CONNECTION_BASED_THREAT': 4.0    # Network-based triggers are basic
    }
    
    total_complexity = sum(complexity_weights.get(p.pattern_type, 3.0) for p in patterns)
    max_possible = len(patterns) * 10.0
    return min(100.0, (total_complexity / max_possible) * 100) if max_possible > 0 else 0.0

def calculate_payload_severity(patterns: list) -> float:
    """Calculate severity of potential payloads (0-100)"""
    if not patterns:
        return 0.0
    
    severity_weights = {
        'CRITICAL_BOMB': 10.0,
        'HIGH_RISK': 7.0,
        'MEDIUM_RISK': 4.0,
        'LOW_RISK': 2.0,
        'SUSPICIOUS': 1.0
    }
    
    total_severity = sum(severity_weights.get(p.severity, 1.0) for p in patterns)
    max_possible = len(patterns) * 10.0
    return min(100.0, (total_severity / max_possible) * 100) if max_possible > 0 else 0.0

def calculate_shield_effectiveness(shield_status: str, patterns: list) -> float:
    """Calculate threat shield effectiveness percentage"""
    if shield_status == 'PROTECTED':
        return 95.0
    elif shield_status == 'BLOCKED':
        critical_patterns = len([p for p in patterns if p.severity == 'CRITICAL_BOMB'])
        if critical_patterns == 0:
            return 75.0
        return max(50.0, 75.0 - (critical_patterns * 5.0))
    elif shield_status == 'ALERT':
        return 60.0
    else:
        return 25.0

def get_most_dangerous_patterns(patterns: list) -> list:
    """Get top 3 most dangerous logic bomb patterns"""
    if not patterns:
        return []
    
    # Sort by severity and confidence
    sorted_patterns = sorted(
        patterns, 
        key=lambda p: (
            {'CRITICAL_BOMB': 5, 'HIGH_RISK': 4, 'MEDIUM_RISK': 3, 'LOW_RISK': 2, 'SUSPICIOUS': 1}.get(p.severity, 1),
            p.confidence
        ),
        reverse=True
    )
    
    return [
        {
            'pattern_type': p.pattern_type,
            'severity': p.severity,
            'confidence': p.confidence,
            'description': p.description,
            'trigger_analysis': p.trigger_analysis,
            'payload_analysis': p.payload_analysis
        }
        for p in sorted_patterns[:3]
    ]

def generate_action_recommendations(patterns: list, threat_intelligence: dict) -> list:
    """Generate specific action recommendations based on detected patterns"""
    recommendations = []
    
    # Pattern-specific recommendations
    pattern_counts = {}
    for p in patterns:
        pattern_counts[p.pattern_type] = pattern_counts.get(p.pattern_type, 0) + 1
    
    if pattern_counts.get('SCHEDULED_THREAT', 0) > 0:
        recommendations.append(f"URGENT: {pattern_counts['SCHEDULED_THREAT']} time bomb(s) detected - Review all date/time conditions immediately")
    
    if pattern_counts.get('DESTRUCTIVE_PAYLOAD', 0) > 0:
        recommendations.append(f"CRITICAL: {pattern_counts['DESTRUCTIVE_PAYLOAD']} destructive payload(s) found - Isolate and neutralize immediately")
    
    if pattern_counts.get('TARGETED_ATTACK', 0) > 0:
        recommendations.append(f"HIGH PRIORITY: {pattern_counts['TARGETED_ATTACK']} user-targeted bomb(s) detected - Review user authentication logic")
    
    if pattern_counts.get('EXECUTION_TRIGGER', 0) > 0:
        recommendations.append(f"MEDIUM PRIORITY: {pattern_counts['EXECUTION_TRIGGER']} counter-based trigger(s) - Review execution counting mechanisms")
    
    # Severity-based recommendations
    critical_count = len([p for p in patterns if p.severity == 'CRITICAL_BOMB'])
    if critical_count > 3:
        recommendations.append("SYSTEM ALERT: Multiple critical logic bombs detected - Consider code quarantine")
    
    # Threat level recommendations
    threat_level = threat_intelligence.get('threat_level', 'UNKNOWN')
    if threat_level == 'CRITICAL':
        recommendations.append("IMMEDIATE ACTION: Critical threat level reached - Activate incident response")
    elif threat_level == 'HIGH':
        recommendations.append("ESCALATE: High threat level - Notify security team immediately")
    
    return recommendations[:5]  # Top 5 recommendations

def export_threat_prompts(issues: list, output_dir: Path):
    """Export threat analysis prompts for AI assistance"""
    if output_dir.exists():
        for file in output_dir.glob("*.md"):
            file.unlink()
    else:
        output_dir.mkdir(parents=True, exist_ok=True)

    for issue in issues:
        safe_file = issue.file_path.replace('/', '_').replace('\\', '_')
        file_name = f"{safe_file}_L{issue.line_number}_{issue.rule_id}.md"

        with open(output_dir / file_name, 'w', encoding='utf-8') as f:
            f.write(f"## ThreatGuard Pro - Logic Bomb Analysis\n")
            f.write(f"**File:** {issue.file_path} | **Line:** {issue.line_number}\n")
            f.write(f"**Threat Type:** {issue.type}\n")
            f.write(f"**Severity:** {issue.severity}\n")
            f.write(f"**Rule ID:** {issue.rule_id}\n")
            f.write(f"**Message:** {issue.message}\n")
            f.write(f"**Threat Level:** {getattr(issue, 'threat_level', 'UNKNOWN')}\n")
            f.write(f"**Trigger Analysis:** {getattr(issue, 'trigger_analysis', 'Analysis pending')}\n")
            f.write(f"**Payload Analysis:** {getattr(issue, 'payload_analysis', 'Analysis pending')}\n")
            f.write(f"**Code Snippet:**\n```\n{issue.code_snippet}\n```\n")
            f.write(f"**Neutralization Guide:** {issue.suggested_fix or 'Review and neutralize based on threat analysis.'}\n")

@app.route('/api/threat-prompts/download')
def download_threat_prompts():
    """Download threat analysis prompts as zip"""
    try:
        prompt_dir = detector.data_dir / "threat_prompts"
        if not prompt_dir.exists():
            return jsonify({'error': 'No threat prompts found'}), 404

        memory_file = io.BytesIO()
        with zipfile.ZipFile(memory_file, 'w') as zf:
            for file_path in prompt_dir.glob("*.md"):
                zf.write(file_path, arcname=file_path.name)
        memory_file.seek(0)

        return send_file(
            memory_file,
            mimetype='application/zip',
            download_name='threatguard_prompts.zip',
            as_attachment=True
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

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
        'effort_minutes': getattr(issue, 'effort', 0),
        'threat_level': getattr(issue, 'threat_level', 'UNKNOWN'),
        'trigger_analysis': getattr(issue, 'trigger_analysis', ''),
        'payload_analysis': getattr(issue, 'payload_analysis', '')
    }

def scan_file_content(file_name: str, content: str, rules: list, file_id: str) -> list:
    """Scan file content with logic bomb detection rules"""
    import re
    issues = []
    lines = content.splitlines()

    for rule in rules:
        try:
            pattern = re.compile(rule.pattern, re.IGNORECASE | re.MULTILINE)

            for line_num, line in enumerate(lines, 1):
                matches = pattern.finditer(line)
                for match in matches:
                    issue = detector.issue_manager.create_issue(
                        rule_id=rule.id,
                        file_path=file_name,
                        line_number=line_num,
                        column=match.start() + 1,
                        message=rule.description,
                        severity=rule.severity,
                        issue_type=rule.type,
                        code_snippet=line.strip(),
                        suggested_fix=generate_neutralization_suggestion(rule, line.strip())
                    )
                    issue.effort = rule.remediation_effort
                    issues.append(issue)

        except re.error as e:
            print(f"⚠️ Invalid regex in rule {rule.id}: {e}")

    return issues

def generate_neutralization_suggestion(rule, code_snippet: str) -> str:
    """Generate specific neutralization suggestions based on rule and code"""
    suggestions = {
        'logic-bomb-time-trigger': f"CRITICAL: Remove time-based conditional logic. Use proper scheduling systems instead.",
        'logic-bomb-user-targeted': f"CRITICAL: Remove user-specific targeting logic. Implement proper access controls.",
        'logic-bomb-execution-counter': f"Remove counter-based triggers. Use proper iteration controls if needed.",
        'logic-bomb-environment-condition': f"Remove environment-specific triggers. Use configuration management instead.",
        'destructive-payload-detector': f"URGENT: Remove destructive operations immediately. Implement proper data management."
    }
    
    base_suggestion = suggestions.get(rule.id, "Neutralize suspicious conditional logic according to security best practices")
    
    # Add context-specific suggestions for logic bombs
    if 'delete' in code_snippet.lower() or 'remove' in code_snippet.lower():
        return f"{base_suggestion} HIGH RISK: Destructive file operations detected."
    elif 'format' in code_snippet.lower():
        return f"{base_suggestion} CRITICAL RISK: System formatting operations detected."
    elif any(trigger in code_snippet.lower() for trigger in ['date', 'time', 'user', 'count']):
        return f"{base_suggestion} Conditional trigger mechanism detected."
    
    return base_suggestion

@app.route('/api/export-threats')
def export_threat_data():
    """Export all threat data"""
    try:
        export_data = {
            'export_timestamp': datetime.now().isoformat(),
            'export_type': 'threatguard_threat_data',
            'threat_rules': [
                {
                    'id': rule.id,
                    'name': rule.name,
                    'description': rule.description,
                    'severity': rule.severity,
                    'type': rule.type,
                    'language': rule.language,
                    'pattern': rule.pattern,
                    'threat_category': getattr(rule, 'threat_category', 'UNKNOWN'),
                    'remediation_effort': rule.remediation_effort,
                    'tags': rule.tags,
                    'enabled': rule.enabled
                }
                for rule in detector.rules_engine.rules.values()
            ],
            'threat_shields': [
                {
                    'id': shield.id,
                    'name': shield.name,
                    'protection_rules': shield.protection_rules,
                    'is_default': shield.is_default,
                    'threat_categories': shield.threat_categories,
                    'risk_threshold': shield.risk_threshold
                }
                for shield in detector.threat_shields.shields.values()
            ],
            'active_threats': [
                {
                    'id': issue.id,
                    'rule_id': issue.rule_id,
                    'file_path': issue.file_path,
                    'line_number': issue.line_number,
                    'message': issue.message,
                    'severity': issue.severity,
                    'type': issue.type,
                    'status': issue.status,
                    'threat_level': getattr(issue, 'threat_level', 'UNKNOWN'),
                    'trigger_analysis': getattr(issue, 'trigger_analysis', ''),
                    'payload_analysis': getattr(issue, 'payload_analysis', ''),
                    'creation_date': issue.creation_date,
                    'code_snippet': issue.code_snippet,
                    'suggested_fix': issue.suggested_fix
                }
                for issue in detector.issue_manager.issues.values()
            ],
            'threat_intelligence_summary': [
                {
                    'scan_id': scan.scan_id,
                    'project_id': scan.project_id,
                    'timestamp': scan.timestamp,
                    'logic_bomb_risk_score': getattr(scan, 'logic_bomb_risk_score', 0),
                    'threat_shield_status': scan.threat_shield_status,
                    'threat_level': scan.threat_intelligence.get('threat_level', 'UNKNOWN') if scan.threat_intelligence else 'UNKNOWN',
                    'threats_detected': len(scan.issues)
                }
                for scan in detector.scan_history
            ]
        }
        
        response = app.response_class(
            response=json.dumps(export_data, indent=2),
            status=200,
            mimetype='application/json'
        )
        response.headers['Content-Disposition'] = 'attachment; filename=threatguard_threat_export.json'
        
        return response
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """System health check for ThreatGuard Pro"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0',
        'scanner_status': 'operational',
        'logic_bomb_detection': 'enabled',
        'threat_shields': 'active',
        'supported_languages': list(advanced_detector.supported_languages.values()),
        'data_directory': str(detector.data_dir),
        'threat_rules_count': len(detector.rules_engine.rules),
        'threat_shields_count': len(detector.threat_shields.shields),
        'total_threats': len(detector.issue_manager.issues),
        'active_threats': len([i for i in detector.issue_manager.issues.values() if i.status == "ACTIVE_THREAT"]),
        'scan_history_count': len(detector.scan_history),
        'system_focus': 'Logic Bomb Detection & Threat Intelligence'
    })

if __name__ == '__main__':
    print("🛡️ ThreatGuard Pro - Command Center API Server")
    print("=" * 60)
    print("🎯 Logic Bomb Detection System Active")
    print("🛡️ Threat Shield Protection Enabled")
    print("🧠 Advanced Threat Intelligence Online")
    print("\n📊 API Endpoints:")
    print("  • POST /api/logic-bomb-scan - Start logic bomb detection")
    print("  • GET  /api/command-center/metrics - Command center data")
    print("  • GET  /api/threats - List all threats")
    print("  • GET  /api/threat-shields - Threat shield management")
    print("  • GET  /api/threat-intelligence - Threat intelligence center")
    print("  • POST /api/scan/files - File upload scanning")
    print("  • GET  /api/export-threats - Export threat data")
    print("="*60)
    
    app.run(host='127.0.0.1', port=5000, debug=True)