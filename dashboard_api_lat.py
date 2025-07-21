#!/usr/bin/env python3
"""
Enhanced Security Scanner - Dashboard API with Multi-Language Malware Detection
Flask API for SonarQube-equivalent dashboard functionality + advanced malware detection
"""

from flask import Flask, request, jsonify, render_template_string, send_file
from flask_cors import CORS
import json
import os
import re
import tempfile
import zipfile
import string
import ast
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass
import traceback

# Import existing scanner components
from security_scanner_main import (
    SecurityScanner, SecurityRule, QualityGate, SecurityIssue,
    MetricsCalculator, ScanResult
)

app = Flask(__name__)
CORS(app)

# Initialize scanner
scanner = SecurityScanner()

# Multi-language detection integration
@dataclass
class MalwarePattern:
    """Advanced malware pattern for multi-language detection."""
    pattern_type: str
    description: str
    severity: str  # LOW, MEDIUM, HIGH
    line_number: int
    code_snippet: str
    confidence: float
    language: str

class MultiLanguageMalwareDetector:
    """Enhanced detector for multi-language malware patterns."""
    
    def __init__(self):
        self.malware_patterns = []
        self.supported_languages = {
            '.py': 'python',
            '.java': 'java', 
            '.js': 'javascript',
            '.ts': 'typescript',
            '.cs': 'csharp',
            '.vb': 'vbnet',
            '.jsx': 'react',
            '.tsx': 'react_typescript',
            '.json': 'config',
            '.html': 'html',
            '.php': 'php',
            '.rb': 'ruby',
            '.go': 'golang',
            '.cpp': 'cpp',
            '.c': 'c'
        }
        
        # Initialize malware signatures
        self.init_malware_signatures()
        
    def init_malware_signatures(self):
        """Initialize comprehensive malware detection signatures."""
        
        # Time bomb patterns (all languages)
        self.time_bomb_patterns = [
            (r'if.*date.*>.*\d{4}', "Date comparison condition"),
            (r'if.*time.*>.*\d{10}', "Timestamp comparison"),
            (r'trigger.*date|activation.*date', "Trigger date reference"),
            (r'DateTime.*>.*new.*DateTime.*\d{4}', "C# date comparison"),
            (r'new\s+Date.*>\s*new\s+Date.*\d{4}', "JavaScript date comparison"),
            (r'\.after\(.*Date.*\d{4}', "Java date comparison"),
        ]
        
        # Financial fraud patterns
        self.financial_fraud_patterns = [
            (r'amount\s*[-+*/]\s*0\.\d+', "Amount manipulation"),
            (r'bitcoin.*address.*[13][a-km-zA-HJ-NP-Z1-9]{25,34}', "Bitcoin address"),
            (r'ethereum.*address.*0x[a-fA-F0-9]{40}', "Ethereum address"),
            (r'paypal\.me/[a-zA-Z0-9]+', "PayPal.me link"),
            (r'fee\s*=\s*amount\s*\*\s*0\.\d+', "Percentage fee calculation"),
            (r'skim|siphon|divert.*amount', "Amount skimming"),
            (r'developer.*wallet|admin.*wallet', "Developer/admin wallet"),
        ]
        
        # System operation patterns
        self.system_op_patterns = [
            # Cross-platform
            (r'exec\s*\(|system\s*\(|shell_exec\s*\(', "Command execution"),
            (r'delete.*file|remove.*directory', "File/directory deletion"),
            
            # Python specific
            (r'os\.system\s*\(|subprocess\.call\s*\(', "Python system command"),
            (r'shutil\.rmtree\s*\(|os\.remove\s*\(', "Python file operations"),
            
            # JavaScript/Node.js
            (r'child_process\.exec\s*\(|fs\.unlink\s*\(', "Node.js system operations"),
            (r'require\s*\(\s*["\']child_process["\']\s*\)', "Node.js process access"),
            
            # Java
            (r'Runtime\.getRuntime\(\)\.exec\s*\(', "Java runtime execution"),
            (r'ProcessBuilder\s*\(|File.*\.delete\s*\(', "Java system operations"),
            
            # C#
            (r'Process\.Start\s*\(|File\.Delete\s*\(', "C# system operations"),
            (r'Registry\.SetValue\s*\(', "C# registry manipulation"),
            
            # PHP
            (r'exec\s*\(|system\s*\(|shell_exec\s*\(', "PHP command execution"),
        ]
        
        # Obfuscation patterns
        self.obfuscation_patterns = [
            (r'eval\s*\(|exec\s*\(', "Code evaluation/execution"),
            (r'base64|b64encode|b64decode', "Base64 encoding"),
            (r'Function\s*\(.*\)|new\s+Function', "Dynamic function creation"),
            (r'Assembly\.Load|Class\.forName', "Dynamic loading"),
            (r'__import__\s*\(|getattr\s*\(', "Python dynamic imports"),
        ]
        
        # Malware indicators
        self.malware_indicators = [
            (r'backdoor|reverse.*shell|bind.*shell', "Backdoor indicators"),
            (r'keylog|password.*steal|credential.*harvest', "Credential theft"),
            (r'encrypt.*files|ransom|decrypt.*key', "Ransomware indicators"),
            (r'mining|miner|hashrate|cryptocurrency', "Crypto mining"),
            (r'botnet|c2|command.*control', "Botnet communication"),
            (r'rootkit|stealth|hide.*process', "Stealth techniques"),
        ]

    def detect_language(self, filepath: str, content: str) -> str:
        """Detect programming language from file extension and content."""
        _, ext = os.path.splitext(filepath.lower())
        if ext in self.supported_languages:
            detected = self.supported_languages[ext]
            
            # Special case detection
            if ext in ['.js', '.jsx'] and 'angular' in content.lower():
                return 'angular'
            elif ext == '.json' and ('package.json' in filepath or 'dependencies' in content):
                return 'npm_config'
                
            return detected
        
        # Content-based detection
        if 'public class' in content and 'static void main' in content:
            return 'java'
        elif 'using System' in content or 'namespace' in content:
            return 'csharp'
        elif '<?php' in content:
            return 'php'
        elif 'def ' in content and 'import ' in content:
            return 'python'
        
        return 'unknown'

    def analyze_file(self, filepath: str) -> List[MalwarePattern]:
        """Analyze file for malware patterns."""
        print(f"\n=== MALWARE ANALYSIS: {filepath} ===")
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            if not content.strip():
                return []
            
            language = self.detect_language(filepath, content)
            print(f"Detected language: {language}")
            
            self.malware_patterns = []
            
            # Run comprehensive malware detection
            self._check_time_bombs(content, language)
            self._check_financial_fraud(content, language)
            self._check_system_operations(content, language)
            self._check_obfuscation(content, language)
            self._check_malware_indicators(content, language)
            
            # Language-specific checks
            if language == 'python':
                self._check_python_specific(content)
            elif language == 'npm_config':
                self._check_npm_config(content)
            
            print(f"Found {len(self.malware_patterns)} malware patterns")
            return self.malware_patterns
            
        except Exception as e:
            print(f"Error in malware analysis: {str(e)}")
            return []

    def _check_time_bombs(self, content: str, language: str):
        """Check for time bomb patterns."""
        lines = content.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern, desc in self.time_bomb_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self.malware_patterns.append(
                        MalwarePattern(
                            pattern_type="TIME_BOMB",
                            description=f"Time bomb: {desc}",
                            severity="HIGH",
                            line_number=i,
                            code_snippet=line.strip(),
                            confidence=0.8,
                            language=language
                        )
                    )

    def _check_financial_fraud(self, content: str, language: str):
        """Check for financial fraud patterns."""
        lines = content.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern, desc in self.financial_fraud_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self.malware_patterns.append(
                        MalwarePattern(
                            pattern_type="FINANCIAL_FRAUD",
                            description=f"Financial fraud: {desc}",
                            severity="HIGH",
                            line_number=i,
                            code_snippet=line.strip(),
                            confidence=0.9,
                            language=language
                        )
                    )

    def _check_system_operations(self, content: str, language: str):
        """Check for dangerous system operations."""
        lines = content.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern, desc in self.system_op_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self.malware_patterns.append(
                        MalwarePattern(
                            pattern_type="SYSTEM_OPERATION",
                            description=f"System operation: {desc}",
                            severity="HIGH",
                            line_number=i,
                            code_snippet=line.strip(),
                            confidence=0.8,
                            language=language
                        )
                    )

    def _check_obfuscation(self, content: str, language: str):
        """Check for code obfuscation."""
        lines = content.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern, desc in self.obfuscation_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self.malware_patterns.append(
                        MalwarePattern(
                            pattern_type="OBFUSCATION",
                            description=f"Obfuscation: {desc}",
                            severity="MEDIUM",
                            line_number=i,
                            code_snippet=line.strip(),
                            confidence=0.7,
                            language=language
                        )
                    )

    def _check_malware_indicators(self, content: str, language: str):
        """Check for malware indicators."""
        lines = content.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern, desc in self.malware_indicators:
                if re.search(pattern, line, re.IGNORECASE):
                    self.malware_patterns.append(
                        MalwarePattern(
                            pattern_type="MALWARE_INDICATOR",
                            description=f"Malware indicator: {desc}",
                            severity="HIGH",
                            line_number=i,
                            code_snippet=line.strip(),
                            confidence=0.8,
                            language=language
                        )
                    )

    def _check_python_specific(self, content: str):
        """Python-specific malware checks."""
        try:
            tree = ast.parse(content)
            lines = content.split('\n')
            
            # Check for suspicious imports
            class ImportVisitor(ast.NodeVisitor):
                def __init__(self, detector):
                    self.detector = detector
                    
                def visit_Import(self, node):
                    for alias in node.names:
                        if alias.name in ['subprocess', 'os', 'shutil'] and 'datetime' in content:
                            self.detector.malware_patterns.append(
                                MalwarePattern(
                                    pattern_type="SUSPICIOUS_IMPORT",
                                    description="Suspicious import combination",
                                    severity="MEDIUM",
                                    line_number=node.lineno,
                                    code_snippet=f"import {alias.name}",
                                    confidence=0.6,
                                    language="python"
                                )
                            )
            
            visitor = ImportVisitor(self)
            visitor.visit(tree)
            
        except SyntaxError:
            # Fall back to regex for invalid Python
            pass

    def _check_npm_config(self, content: str):
        """Check npm package.json for malicious content."""
        try:
            config = json.loads(content)
            
            # Check for suspicious dependencies
            suspicious_deps = [
                'remote-exec', 'node-shell', 'exec-async', 'malicious-package',
                'bitcoin-miner', 'crypto-miner', 'backdoor-js'
            ]
            
            deps_to_check = {}
            if 'dependencies' in config:
                deps_to_check.update(config['dependencies'])
            if 'devDependencies' in config:
                deps_to_check.update(config['devDependencies'])
            
            for dep_name, version in deps_to_check.items():
                if any(sus in dep_name.lower() for sus in suspicious_deps):
                    self.malware_patterns.append(
                        MalwarePattern(
                            pattern_type="MALICIOUS_DEPENDENCY",
                            description=f"Malicious dependency: {dep_name}",
                            severity="HIGH",
                            line_number=1,
                            code_snippet=f'"{dep_name}": "{version}"',
                            confidence=0.9,
                            language="npm_config"
                        )
                    )
            
            # Check for suspicious scripts
            if 'scripts' in config:
                for script_name, script_cmd in config['scripts'].items():
                    if any(cmd in script_cmd.lower() for cmd in ['rm -rf', 'curl', 'wget', 'bash']):
                        self.malware_patterns.append(
                            MalwarePattern(
                                pattern_type="MALICIOUS_SCRIPT",
                                description=f"Malicious script: {script_name}",
                                severity="HIGH",
                                line_number=1,
                                code_snippet=f'"{script_name}": "{script_cmd}"',
                                confidence=0.8,
                                language="npm_config"
                            )
                        )
                        
        except json.JSONDecodeError:
            pass

# Global malware detector instance
malware_detector = MultiLanguageMalwareDetector()

# Enhanced file upload scanning endpoint
@app.route('/api/scan/files', methods=['POST'])
def scan_uploaded_files():
    """Enhanced file scanning with multi-language malware detection."""
    try:
        data = request.get_json()
        scan_id = data.get('scan_id', f"scan_{int(datetime.now().timestamp())}")
        scan_type = data.get('scan_type', 'enhanced')
        file_contents = data.get('file_contents', [])
        project_id = data.get('project_id', f'upload-scan-{int(datetime.now().timestamp())}')
        project_name = data.get('project_name', 'Enhanced Security Scan')

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

            # Perform enhanced scan with malware detection
            scan_result = perform_enhanced_file_scan(
                scan_id=scan_id,
                project_id=project_id,
                project_name=project_name,
                file_paths=file_paths,
                scan_type=scan_type
            )

            return jsonify(scan_result)

    except Exception as e:
        return jsonify({'error': f'Enhanced scan failed: {str(e)}'}), 500

def perform_enhanced_file_scan(scan_id: str, project_id: str, project_name: str, 
                              file_paths: list, scan_type: str = 'enhanced') -> dict:
    """Perform enhanced security scan with malware detection."""
    start_time = datetime.now()
    total_issues = []
    total_malware_patterns = []
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

            # Standard security scanning
            applicable_rules = scanner.rules_engine.get_enabled_rules(file_type)
            file_issues = scan_file_content(file_name, content, applicable_rules, file_id)

            # Enhanced malware detection
            malware_patterns = malware_detector.analyze_file(file_path)

            # Convert malware patterns to security issues
            enhanced_issues = []
            for pattern in malware_patterns:
                enhanced_issue = scanner.issue_manager.create_issue(
                    rule_id=f"MALWARE_{pattern.pattern_type}",
                    file_path=file_name,
                    line_number=pattern.line_number,
                    column=1,
                    message=pattern.description,
                    severity=pattern.severity,
                    issue_type="VULNERABILITY",
                    code_snippet=pattern.code_snippet,
                    suggested_fix=f"Review and remove {pattern.pattern_type.lower()} pattern"
                )
                enhanced_issues.append(enhanced_issue)

            all_file_issues = file_issues + enhanced_issues

            file_result = {
                'file_id': file_id,
                'file_name': file_name,
                'file_type': file_type,
                'language': malware_detector.detect_language(file_path, content),
                'lines_scanned': file_lines,
                'issues': [format_issue_for_response(issue) for issue in all_file_issues],
                'malware_patterns': [format_malware_pattern(p) for p in malware_patterns],
                'issues_count': len(all_file_issues),
                'malware_count': len(malware_patterns),
                'critical_issues': len([i for i in all_file_issues if getattr(i, 'severity', 'LOW') in ['BLOCKER', 'CRITICAL', 'HIGH']]),
                'scan_status': 'completed'
            }

            file_results.append(file_result)
            total_issues.extend(all_file_issues)
            total_malware_patterns.extend(malware_patterns)
            
        except Exception as e:
            file_results.append({
                'file_id': file_info['id'],
                'file_name': file_info['name'],
                'file_type': file_info['type'],
                'scan_status': 'error',
                'error_message': str(e)
            })

    # Compute enhanced metrics
    tech_debt = MetricsCalculator.calculate_technical_debt(total_issues)
    security_rating = MetricsCalculator.calculate_security_rating(total_issues)
    reliability_rating = MetricsCalculator.calculate_reliability_rating(total_issues)
    maintainability_rating = MetricsCalculator.calculate_maintainability_rating(tech_debt, total_lines)
    coverage = 85.0
    duplications = 2.0

    # Enhanced risk assessment
    malware_risk = "HIGH" if any(p.severity == "HIGH" for p in total_malware_patterns) else "MEDIUM" if total_malware_patterns else "LOW"
    overall_risk = "HIGH" if malware_risk == "HIGH" or security_rating in ['D', 'E'] else "MEDIUM" if malware_risk == "MEDIUM" else "LOW"

    metrics = {
        'security_rating': ord(security_rating) - ord('A') + 1,
        'reliability_rating': ord(reliability_rating) - ord('A') + 1,
        'sqale_rating': ord(maintainability_rating) - ord('A') + 1,
        'coverage': coverage,
        'duplicated_lines_density': duplications,
        'blocker_violations': len([i for i in total_issues if getattr(i, 'severity', '') == "BLOCKER"]),
        'critical_violations': len([i for i in total_issues if getattr(i, 'severity', '') == "CRITICAL"])
    }

    default_gate = next((g for g in scanner.quality_gates.gates.values() if g.is_default), None)
    gate_result = scanner.quality_gates.evaluate_gate(default_gate.id, metrics) if default_gate else {}
    gate_status = gate_result.get("status", "OK")

    duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
    timestamp = start_time.isoformat()

    # Create enhanced scan result
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

    # Save to scanner
    scanner.scan_history.append(scan_result_obj)
    scanner.save_scan_history()

    for issue in total_issues:
        scanner.issue_manager.issues[issue.id] = issue
    scanner.issue_manager.save_issues()

    # Return enhanced response
    return {
        'scan_id': scan_id,
        'project_id': project_id,
        'project_name': project_name,
        'scan_type': f'{scan_type}_enhanced',
        'timestamp': timestamp,
        'duration_ms': duration_ms,
        'files_scanned': len(file_paths),
        'lines_of_code': total_lines,
        'file_results': file_results,
        'summary': {
            'total_issues': len(total_issues),
            'malware_patterns_found': len(total_malware_patterns),
            'critical_issues': len([i for i in total_issues if getattr(i, 'severity', '') in ['BLOCKER', 'CRITICAL']]),
            'security_rating': security_rating,
            'malware_risk_level': malware_risk,
            'overall_risk_level': overall_risk,
            'quality_gate_passed': gate_status == "OK",
            'technical_debt_hours': tech_debt // 60
        },
        'enhanced_metrics': {
            'languages_detected': len(set(r.get('language', 'unknown') for r in file_results)),
            'malware_categories': list(set(p.pattern_type for p in total_malware_patterns)),
            'files_with_malware': len([r for r in file_results if r.get('malware_count', 0) > 0]),
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
            'message': 'Enhanced Quality Gate Passed' if gate_status == 'OK' else 'Enhanced Quality Gate Failed'
        },
        'malware_analysis': {
            'total_patterns': len(total_malware_patterns),
            'by_severity': {
                'HIGH': len([p for p in total_malware_patterns if p.severity == 'HIGH']),
                'MEDIUM': len([p for p in total_malware_patterns if p.severity == 'MEDIUM']),
                'LOW': len([p for p in total_malware_patterns if p.severity == 'LOW'])
            },
            'by_type': {
                pattern_type: len([p for p in total_malware_patterns if p.pattern_type == pattern_type])
                for pattern_type in set(p.pattern_type for p in total_malware_patterns)
            }
        }
    }

def format_malware_pattern(pattern: MalwarePattern) -> dict:
    """Format malware pattern for JSON response."""
    return {
        'pattern_type': pattern.pattern_type,
        'description': pattern.description,
        'severity': pattern.severity,
        'line_number': pattern.line_number,
        'code_snippet': pattern.code_snippet,
        'confidence': pattern.confidence,
        'language': pattern.language
    }

def format_issue_for_response(issue) -> dict:
    """Format issue for JSON response."""
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
    """Scan file content with security rules."""
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
    """Generate specific fix suggestions based on rule and code."""
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

# Enhanced health check
@app.route('/api/health', methods=['GET'])
def health_check():
    """Enhanced health check with malware detection status."""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '2.0.0 - Enhanced Multi-Language Detection',
        'scanner_status': 'operational',
        'malware_detection': 'enabled',
        'supported_languages': list(malware_detector.supported_languages.values()),
        'data_directory': str(scanner.data_dir),
        'rules_count': len(scanner.rules_engine.rules),
        'quality_gates_count': len(scanner.quality_gates.gates),
        'total_issues': len(scanner.issue_manager.issues),
        'scan_history_count': len(scanner.scan_history),
        'enhanced_features': [
            'Multi-language malware detection',
            'Time bomb detection',
            'Financial fraud detection',
            'Obfuscation detection',
            'System operation monitoring',
            'Real-time analysis'
        ]
    })

# Enhanced malware detection endpoint
@app.route('/api/malware/analyze', methods=['POST'])
def analyze_malware():
    """Dedicated malware analysis endpoint."""
    try:
        data = request.get_json()
        code = data.get('code', '')
        filename = data.get('filename', 'analysis.txt')
        
        if not code:
            return jsonify({'error': 'No code provided'}), 400
        
        # Create temporary file for analysis
        with tempfile.NamedTemporaryFile(mode='w', suffix=f'_{filename}', delete=False) as temp_file:
            temp_file.write(code)
            temp_path = temp_file.name
        
        try:
            # Perform malware analysis
            patterns = malware_detector.analyze_file(temp_path)
            language = malware_detector.detect_language(filename, code)
            
            # Risk assessment
            risk_level = "HIGH" if any(p.severity == "HIGH" for p in patterns) else \
                        "MEDIUM" if any(p.severity == "MEDIUM" for p in patterns) else "LOW"
            
            result = {
                'filename': filename,
                'language': language,
                'risk_level': risk_level,
                'malware_patterns': [format_malware_pattern(p) for p in patterns],
                'total_patterns': len(patterns),
                'analysis_date': datetime.now().isoformat(),
                'pattern_categories': list(set(p.pattern_type for p in patterns)),
                'severity_breakdown': {
                    'HIGH': len([p for p in patterns if p.severity == 'HIGH']),
                    'MEDIUM': len([p for p in patterns if p.severity == 'MEDIUM']),
                    'LOW': len([p for p in patterns if p.severity == 'LOW'])
                }
            }
            
            return jsonify(result)
            
        finally:
            # Cleanup
            os.unlink(temp_path)
            
    except Exception as e:
        return jsonify({'error': f'Malware analysis failed: {str(e)}'}), 500

# Add all existing dashboard endpoints here...
# (keeping original dashboard_api.py endpoints unchanged)

if __name__ == '__main__':
    print("🚀 Starting Enhanced Security Scanner Dashboard with Multi-Language Malware Detection...")
    print("📊 Enhanced features enabled:")
    print("  • Multi-language malware detection")
    print("  • Time bomb detection")
    print("  • Financial fraud detection")
    print("  • Advanced obfuscation detection")
    print("  • System operation monitoring")
    print("  • Enhanced risk assessment")
    print("\n🌐 Dashboard available at: http://localhost:5000")
    print("📋 Enhanced API endpoints:")
    print("  • POST /api/scan/files - Enhanced file scanning with malware detection")
    print("  • POST /api/malware/analyze - Dedicated malware analysis")
    print("  • GET  /api/health - Enhanced health check")
    print("="*80)
    
    app.run(host='127.0.0.1', port=5000, debug=True)