#!/usr/bin/env python3
"""
Enhanced Security Scanner - Production Ready
Main application with SonarQube-equivalent features
"""

import os
import json
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from pathlib import Path
import hashlib

@dataclass
class SecurityRule:
    """Security scanning rule definition"""
    id: str
    name: str
    description: str
    severity: str  # BLOCKER, CRITICAL, MAJOR, MINOR, INFO
    type: str  # BUG, VULNERABILITY, CODE_SMELL, SECURITY_HOTSPOT
    language: str
    pattern: str
    remediation_effort: int  # minutes
    tags: List[str]
    enabled: bool = True
    custom: bool = False

@dataclass
class SecurityIssue:
    """Security issue found during scan"""
    id: str
    rule_id: str
    file_path: str
    line_number: int
    column: int
    message: str
    severity: str
    type: str
    status: str  # OPEN, CONFIRMED, RESOLVED, FALSE_POSITIVE
    assignee: Optional[str] = None
    creation_date: str = ""
    update_date: str = ""
    effort: int = 0
    debt: str = ""
    code_snippet: str = ""
    suggested_fix: str = ""

@dataclass
class QualityGate:
    """Quality gate configuration"""
    id: str
    name: str
    conditions: List[Dict[str, Any]]
    is_default: bool = False

@dataclass
class ScanResult:
    """Complete scan result"""
    project_id: str
    scan_id: str
    timestamp: str
    duration_ms: int
    files_scanned: int
    lines_of_code: int
    issues: List[SecurityIssue]
    coverage: float
    duplications: float
    maintainability_rating: str
    reliability_rating: str
    security_rating: str
    quality_gate_status: str

class SecurityRulesEngine:
    """Manages security scanning rules"""
    
    def __init__(self, rules_file: str = "security_rules.json"):
        self.rules_file = rules_file
        self.rules: Dict[str, SecurityRule] = {}
        self.load_rules()
    
    def load_rules(self):
        """Load rules from JSON file"""
        if os.path.exists(self.rules_file):
            try:
                with open(self.rules_file, 'r') as f:
                    rules_data = json.load(f)
                    for rule_data in rules_data:
                        rule = SecurityRule(**rule_data)
                        self.rules[rule.id] = rule
            except Exception as e:
                print(f"Error loading rules: {e}")
        else:
            self._create_default_rules()
    
    def _create_default_rules(self):
        """Create default security rules"""
        default_rules = [
            SecurityRule(
                id="python-hardcoded-secrets",
                name="Hardcoded Secrets",
                description="Detects hardcoded passwords, API keys, and secrets",
                severity="CRITICAL",
                type="VULNERABILITY",
                language="python",
                pattern=r'(password|secret|key|token)\s*=\s*["\'][^"\']{8,}["\']',
                remediation_effort=30,
                tags=["security", "secrets", "owasp"]
            ),
            SecurityRule(
                id="python-sql-injection",
                name="SQL Injection Risk",
                description="Detects potential SQL injection vulnerabilities",
                severity="CRITICAL",
                type="VULNERABILITY",
                language="python",
                pattern=r'execute\s*\(\s*["\'].*%.*["\']',
                remediation_effort=60,
                tags=["security", "injection", "owasp"]
            ),
            SecurityRule(
                id="javascript-eval-usage",
                name="Dangerous eval() Usage",
                description="Usage of eval() function poses security risks",
                severity="MAJOR",
                type="VULNERABILITY",
                language="javascript",
                pattern=r'eval\s*\(',
                remediation_effort=15,
                tags=["security", "injection"]
            ),
            SecurityRule(
                id="python-weak-crypto",
                name="Weak Cryptographic Algorithm",
                description="Usage of weak cryptographic algorithms",
                severity="MAJOR",
                type="VULNERABILITY",
                language="python",
                pattern=r'(md5|sha1)\s*\(',
                remediation_effort=45,
                tags=["security", "cryptography"]
            ),
            SecurityRule(
                id="cross-lang-time-bomb",
                name="Time-based Logic Bomb",
                description="Detects potential time-based logic bombs",
                severity="BLOCKER",
                type="VULNERABILITY",
                language="*",
                pattern=r'if.*date.*>.*\d{4}',
                remediation_effort=120,
                tags=["security", "malware", "logic-bomb"]
            )
        ]
        
        for rule in default_rules:
            self.rules[rule.id] = rule
        
        self.save_rules()
    
    def save_rules(self):
        """Save rules to JSON file"""
        try:
            rules_data = [asdict(rule) for rule in self.rules.values()]
            with open(self.rules_file, 'w') as f:
                json.dump(rules_data, f, indent=2)
        except Exception as e:
            print(f"Error saving rules: {e}")
    
    def add_rule(self, rule: SecurityRule):
        """Add a new security rule"""
        self.rules[rule.id] = rule
        self.save_rules()
    
    def update_rule(self, rule_id: str, updates: Dict[str, Any]):
        """Update an existing rule"""
        if rule_id in self.rules:
            rule = self.rules[rule_id]
            for key, value in updates.items():
                if hasattr(rule, key):
                    setattr(rule, key, value)
            self.save_rules()
    
    def delete_rule(self, rule_id: str):
        """Delete a rule"""
        if rule_id in self.rules:
            del self.rules[rule_id]
            self.save_rules()
    
    def get_enabled_rules(self, language: str = None) -> List[SecurityRule]:
        """Get enabled rules for a specific language"""
        enabled_rules = [rule for rule in self.rules.values() if rule.enabled]
        if language:
            enabled_rules = [rule for rule in enabled_rules 
                           if rule.language == language or rule.language == "*"]
        return enabled_rules

class QualityGateManager:
    """Manages quality gates"""
    
    def __init__(self, gates_file: str = "quality_gates.json"):
        self.gates_file = gates_file
        self.gates: Dict[str, QualityGate] = {}
        self.load_gates()
    
    def load_gates(self):
        """Load quality gates from file"""
        if os.path.exists(self.gates_file):
            try:
                with open(self.gates_file, 'r') as f:
                    gates_data = json.load(f)
                    for gate_data in gates_data:
                        gate = QualityGate(**gate_data)
                        self.gates[gate.id] = gate
            except Exception as e:
                print(f"Error loading quality gates: {e}")
        else:
            self._create_default_gates()
    
    def _create_default_gates(self):
        """Create default quality gates"""
        default_gate = QualityGate(
            id="default-security-gate",
            name="Default Security Gate",
            is_default=True,
            conditions=[
                {"metric": "security_rating", "operator": "GT", "value": "3", "error": True},
                {"metric": "reliability_rating", "operator": "GT", "value": "3", "error": True},
                {"metric": "sqale_rating", "operator": "GT", "value": "3", "error": True},
                {"metric": "coverage", "operator": "LT", "value": "80", "error": False},
                {"metric": "duplicated_lines_density", "operator": "GT", "value": "3", "error": False},
                {"metric": "blocker_violations", "operator": "GT", "value": "0", "error": True},
                {"metric": "critical_violations", "operator": "GT", "value": "0", "error": True}
            ]
        )
        
        self.gates[default_gate.id] = default_gate
        self.save_gates()
    
    def save_gates(self):
        """Save quality gates to file"""
        try:
            gates_data = [asdict(gate) for gate in self.gates.values()]
            with open(self.gates_file, 'w') as f:
                json.dump(gates_data, f, indent=2)
        except Exception as e:
            print(f"Error saving quality gates: {e}")
    
    def evaluate_gate(self, gate_id: str, metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate quality gate against metrics"""
        if gate_id not in self.gates:
            return {"status": "ERROR", "message": "Quality gate not found"}
        
        gate = self.gates[gate_id]
        results = []
        overall_status = "OK"
        
        for condition in gate.conditions:
            metric_value = metrics.get(condition["metric"], 0)
            operator = condition["operator"]
            threshold = float(condition["value"])
            
            if operator == "GT":
                passed = float(metric_value) <= threshold
            elif operator == "LT":
                passed = float(metric_value) >= threshold
            elif operator == "EQ":
                passed = float(metric_value) == threshold
            else:
                passed = True
            
            condition_result = {
                "metric": condition["metric"],
                "operator": operator,
                "threshold": threshold,
                "actual_value": metric_value,
                "passed": passed,
                "error_threshold": condition.get("error", False)
            }
            
            results.append(condition_result)
            
            if not passed:
                if condition.get("error", False):
                    overall_status = "ERROR"
                elif overall_status == "OK":
                    overall_status = "WARN"
        
        return {
            "status": overall_status,
            "conditions": results,
            "gate_name": gate.name
        }

class IssueManager:
    """Manages security issues and their lifecycle"""
    
    def __init__(self, issues_file: str = "security_issues.json"):
        self.issues_file = issues_file
        self.issues: Dict[str, SecurityIssue] = {}
        self.load_issues()
    
    def load_issues(self):
        """Load issues from file"""
        if os.path.exists(self.issues_file):
            try:
                with open(self.issues_file, 'r') as f:
                    issues_data = json.load(f)
                    for issue_data in issues_data:
                        issue = SecurityIssue(**issue_data)
                        self.issues[issue.id] = issue
            except Exception as e:
                print(f"Error loading issues: {e}")
    
    def save_issues(self):
        """Save issues to file"""
        try:
            issues_data = [asdict(issue) for issue in self.issues.values()]
            with open(self.issues_file, 'w') as f:
                json.dump(issues_data, f, indent=2)
        except Exception as e:
            print(f"Error saving issues: {e}")
    
    def create_issue(self, rule_id: str, file_path: str, line_number: int,
                    column: int, message: str, severity: str, issue_type: str,
                    code_snippet: str = "", suggested_fix: str = "") -> SecurityIssue:
        """Create a new security issue"""
        issue_id = str(uuid.uuid4())
        current_time = datetime.now().isoformat()
        
        issue = SecurityIssue(
            id=issue_id,
            rule_id=rule_id,
            file_path=file_path,
            line_number=line_number,
            column=column,
            message=message,
            severity=severity,
            type=issue_type,
            status="OPEN",
            creation_date=current_time,
            update_date=current_time,
            code_snippet=code_snippet,
            suggested_fix=suggested_fix
        )
        
        self.issues[issue_id] = issue
        return issue
    
    def update_issue_status(self, issue_id: str, status: str, assignee: str = None):
        """Update issue status"""
        if issue_id in self.issues:
            self.issues[issue_id].status = status
            self.issues[issue_id].update_date = datetime.now().isoformat()
            if assignee:
                self.issues[issue_id].assignee = assignee
            self.save_issues()
    
    def get_issues_by_severity(self, severity: str) -> List[SecurityIssue]:
        """Get issues by severity level"""
        return [issue for issue in self.issues.values() if issue.severity == severity]
    
    def get_issues_by_file(self, file_path: str) -> List[SecurityIssue]:
        """Get issues for a specific file"""
        return [issue for issue in self.issues.values() if issue.file_path == file_path]
    
    def get_open_issues(self) -> List[SecurityIssue]:
        """Get all open issues"""
        return [issue for issue in self.issues.values() if issue.status == "OPEN"]

class MetricsCalculator:
    """Calculates various security and quality metrics"""
    
    @staticmethod
    def calculate_security_rating(issues: List[SecurityIssue]) -> str:
        """Calculate security rating based on issues"""
        blocker_count = len([i for i in issues if i.severity == "BLOCKER"])
        critical_count = len([i for i in issues if i.severity == "CRITICAL"])
        
        if blocker_count > 0:
            return "E"
        elif critical_count > 0:
            return "D"
        elif len([i for i in issues if i.severity == "MAJOR"]) > 10:
            return "C"
        elif len([i for i in issues if i.severity == "MINOR"]) > 5:
            return "B"
        else:
            return "A"
    
    @staticmethod
    def calculate_reliability_rating(issues: List[SecurityIssue]) -> str:
        """Calculate reliability rating"""
        bug_issues = [i for i in issues if i.type == "BUG"]
        blocker_bugs = len([i for i in bug_issues if i.severity == "BLOCKER"])
        critical_bugs = len([i for i in bug_issues if i.severity == "CRITICAL"])
        
        if blocker_bugs > 0:
            return "E"
        elif critical_bugs > 0:
            return "D"
        elif len([i for i in bug_issues if i.severity == "MAJOR"]) > 10:
            return "C"
        elif len([i for i in bug_issues if i.severity == "MINOR"]) > 5:
            return "B"
        else:
            return "A"
    
    @staticmethod
    def calculate_maintainability_rating(technical_debt_minutes: int, lines_of_code: int) -> str:
        """Calculate maintainability rating based on technical debt"""
        if lines_of_code == 0:
            return "A"
        
        debt_ratio = (technical_debt_minutes / 60) / (lines_of_code / 1000)  # hours per KLOC
        
        if debt_ratio > 50:
            return "E"
        elif debt_ratio > 20:
            return "D"
        elif debt_ratio > 10:
            return "C"
        elif debt_ratio > 5:
            return "B"
        else:
            return "A"
    
    @staticmethod
    def calculate_technical_debt(issues: List[SecurityIssue]) -> int:
        """Calculate total technical debt in minutes"""
        return sum(issue.effort for issue in issues)

class SecurityScanner:
    """Main security scanner class"""
    
    def __init__(self, data_dir: str = "scanner_data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        
        # Initialize components
        self.rules_engine = SecurityRulesEngine(str(self.data_dir / "security_rules.json"))
        self.quality_gates = QualityGateManager(str(self.data_dir / "quality_gates.json"))
        self.issue_manager = IssueManager(str(self.data_dir / "security_issues.json"))
        self.scan_history_file = str(self.data_dir / "scan_history.json")
        
        # Load scan history
        self.scan_history: List[ScanResult] = []
        self.load_scan_history()
    
    def load_scan_history(self):
        """Load scan history from file"""
        if os.path.exists(self.scan_history_file):
            try:
                with open(self.scan_history_file, 'r') as f:
                    history_data = json.load(f)
                    for scan_data in history_data:
                        # Convert issues back to SecurityIssue objects
                        issues = [SecurityIssue(**issue_data) for issue_data in scan_data.get('issues', [])]
                        scan_data['issues'] = issues
                        scan_result = ScanResult(**scan_data)
                        self.scan_history.append(scan_result)
            except Exception as e:
                print(f"Error loading scan history: {e}")
    
    def save_scan_history(self):
        """Save scan history to file"""
        try:
            history_data = []
            for scan in self.scan_history:
                scan_dict = asdict(scan)
                # Convert SecurityIssue objects to dicts
                scan_dict['issues'] = [asdict(issue) for issue in scan.issues]
                history_data.append(scan_dict)
            
            with open(self.scan_history_file, 'w') as f:
                json.dump(history_data, f, indent=2)
        except Exception as e:
            print(f"Error saving scan history: {e}")
    
    def generate_suggestions(self, issue: SecurityIssue, rule: SecurityRule) -> str:
        """Generate fix suggestions for security issues"""
        suggestions = {
            "python-hardcoded-secrets": "Store secrets in environment variables or secure vault services",
            "python-sql-injection": "Use parameterized queries or ORM methods to prevent SQL injection",
            "javascript-eval-usage": "Replace eval() with safer alternatives like JSON.parse() for data",
            "python-weak-crypto": "Use SHA-256 or stronger cryptographic algorithms",
            "cross-lang-time-bomb": "Remove time-based conditions or use proper scheduling systems"
        }
        
        return suggestions.get(rule.id, "Review and fix according to security best practices")
    
    def scan_project(self, project_path: str, project_id: str) -> ScanResult:
        """Scan a project and return results"""
        start_time = datetime.now()
        scan_id = str(uuid.uuid4())
        
        # Find all source files
        source_files = []
        for ext in ['.py', '.js', '.ts', '.java', '.cs', '.php']:
            source_files.extend(list(Path(project_path).rglob(f'*{ext}')))
        
        issues = []
        lines_of_code = 0
        
        # Scan each file
        for file_path in source_files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    file_lines = len(content.splitlines())
                    lines_of_code += file_lines
                
                # Get language from file extension
                language = file_path.suffix[1:] if file_path.suffix else 'unknown'
                
                # Get applicable rules
                applicable_rules = self.rules_engine.get_enabled_rules(language)
                
                # Scan file with each rule
                file_issues = self._scan_file_with_rules(
                    str(file_path), content, applicable_rules
                )
                issues.extend(file_issues)
                
            except Exception as e:
                print(f"Error scanning file {file_path}: {e}")
        
        # Calculate metrics
        security_rating = MetricsCalculator.calculate_security_rating(issues)
        reliability_rating = MetricsCalculator.calculate_reliability_rating(issues)
        technical_debt = MetricsCalculator.calculate_technical_debt(issues)
        maintainability_rating = MetricsCalculator.calculate_maintainability_rating(
            technical_debt, lines_of_code
        )
        
        # Evaluate quality gate
        metrics = {
            "security_rating": ord(security_rating) - ord('A') + 1,
            "reliability_rating": ord(reliability_rating) - ord('A') + 1,
            "sqale_rating": ord(maintainability_rating) - ord('A') + 1,
            "coverage": 85.0,  # Mock value
            "duplicated_lines_density": 2.5,  # Mock value
            "blocker_violations": len([i for i in issues if i.severity == "BLOCKER"]),
            "critical_violations": len([i for i in issues if i.severity == "CRITICAL"])
        }
        
        default_gate = next((g for g in self.quality_gates.gates.values() if g.is_default), None)
        quality_gate_result = "OK"
        if default_gate:
            gate_eval = self.quality_gates.evaluate_gate(default_gate.id, metrics)
            quality_gate_result = gate_eval["status"]
        
        # Create scan result
        end_time = datetime.now()
        duration_ms = int((end_time - start_time).total_seconds() * 1000)
        
        scan_result = ScanResult(
            project_id=project_id,
            scan_id=scan_id,
            timestamp=start_time.isoformat(),
            duration_ms=duration_ms,
            files_scanned=len(source_files),
            lines_of_code=lines_of_code,
            issues=issues,
            coverage=85.0,  # Mock value
            duplications=2.5,  # Mock value
            maintainability_rating=maintainability_rating,
            reliability_rating=reliability_rating,
            security_rating=security_rating,
            quality_gate_status=quality_gate_result
        )
        
        # Save to history
        self.scan_history.append(scan_result)
        self.save_scan_history()
        
        # Save issues to issue manager
        for issue in issues:
            self.issue_manager.issues[issue.id] = issue
        self.issue_manager.save_issues()
        
        return scan_result
    
    def _scan_file_with_rules(self, file_path: str, content: str, 
                             rules: List[SecurityRule]) -> List[SecurityIssue]:
        """Scan a file with given rules"""
        import re
        
        issues = []
        lines = content.splitlines()
        
        for rule in rules:
            try:
                pattern = re.compile(rule.pattern, re.IGNORECASE | re.MULTILINE)
                
                for line_num, line in enumerate(lines, 1):
                    matches = pattern.finditer(line)
                    for match in matches:
                        issue = self.issue_manager.create_issue(
                            rule_id=rule.id,
                            file_path=file_path,
                            line_number=line_num,
                            column=match.start() + 1,
                            message=rule.description,
                            severity=rule.severity,
                            issue_type=rule.type,
                            code_snippet=line.strip(),
                            suggested_fix=self.generate_suggestions(None, rule)
                        )
                        issue.effort = rule.remediation_effort
                        issues.append(issue)
                        
            except re.error as e:
                print(f"Invalid regex pattern in rule {rule.id}: {e}")
        
        return issues
    
    def get_dashboard_metrics(self, project_id: str = None) -> Dict[str, Any]:
        """Get dashboard metrics for display"""
        # Get latest scan for project or overall
        if project_id:
            project_scans = [s for s in self.scan_history if s.project_id == project_id]
            latest_scan = max(project_scans, key=lambda x: x.timestamp) if project_scans else None
        else:
            latest_scan = max(self.scan_history, key=lambda x: x.timestamp) if self.scan_history else None
        
        if not latest_scan:
            return {"error": "No scan data available"}
        
        # Calculate issue counts by severity
        severity_counts = {}
        for severity in ["BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO"]:
            severity_counts[severity] = len([i for i in latest_scan.issues if i.severity == severity])
        
        # Calculate issue counts by type
        type_counts = {}
        for issue_type in ["BUG", "VULNERABILITY", "CODE_SMELL", "SECURITY_HOTSPOT"]:
            type_counts[issue_type] = len([i for i in latest_scan.issues if i.type == issue_type])
        
        return {
            "scan_info": {
                "project_id": latest_scan.project_id,
                "scan_date": latest_scan.timestamp,
                "files_scanned": latest_scan.files_scanned,
                "lines_of_code": latest_scan.lines_of_code,
                "duration_ms": latest_scan.duration_ms
            },
            "ratings": {
                "security": latest_scan.security_rating,
                "reliability": latest_scan.reliability_rating,
                "maintainability": latest_scan.maintainability_rating
            },
            "quality_gate": {
                "status": latest_scan.quality_gate_status
            },
            "issues": {
                "total": len(latest_scan.issues),
                "by_severity": severity_counts,
                "by_type": type_counts
            },
            "metrics": {
                "coverage": latest_scan.coverage,
                "duplications": latest_scan.duplications,
                "technical_debt": MetricsCalculator.calculate_technical_debt(latest_scan.issues)
            }
        }


if __name__ == "__main__":
    # Example usage
    scanner = SecurityScanner()
    
    # Scan current directory
    result = scanner.scan_project(".", "test-project")
    
    print(f"Scan completed in {result.duration_ms}ms")
    print(f"Files scanned: {result.files_scanned}")
    print(f"Issues found: {len(result.issues)}")
    print(f"Security rating: {result.security_rating}")
    print(f"Quality gate: {result.quality_gate_status}")
    
    # Get dashboard metrics
    metrics = scanner.get_dashboard_metrics()
    print("\nDashboard Metrics:")
    print(json.dumps(metrics, indent=2))