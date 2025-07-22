#!/usr/bin/env python3
"""
ThreatGuard Pro - Logic Bomb Detection System
Advanced Malicious Code Pattern Detection & Threat Intelligence
Copyright 2025 - Specialized in Logic Bomb & Trigger-Based Threat Detection
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
    """Logic bomb detection rule definition"""
    id: str
    name: str
    description: str
    severity: str  # CRITICAL_BOMB, HIGH_RISK, MEDIUM_RISK, LOW_RISK, SUSPICIOUS
    type: str  # LOGIC_BOMB, SCHEDULED_THREAT, TARGETED_ATTACK, EXECUTION_TRIGGER, DESTRUCTIVE_PAYLOAD
    language: str
    pattern: str
    remediation_effort: int  # minutes
    tags: List[str]
    enabled: bool = True
    custom: bool = False
    threat_category: str = "UNKNOWN"  # NEW: Categorize threat type

@dataclass
class SecurityIssue:
    """Logic bomb security issue found during scan"""
    id: str
    rule_id: str
    file_path: str
    line_number: int
    column: int
    message: str
    severity: str
    type: str
    status: str  # ACTIVE_THREAT, NEUTRALIZED, UNDER_REVIEW, FALSE_POSITIVE
    assignee: Optional[str] = None
    creation_date: str = ""
    update_date: str = ""
    effort: int = 0
    debt: str = ""
    code_snippet: str = ""
    suggested_fix: str = ""
    threat_level: str = "UNKNOWN"  # NEW: Threat assessment
    trigger_analysis: str = ""     # NEW: What triggers this bomb
    payload_analysis: str = ""     # NEW: What damage it could cause

@dataclass
class ThreatShield:
    """Threat protection shield configuration (replaces QualityGate)"""
    id: str
    name: str
    protection_rules: List[Dict[str, Any]]  # Changed from 'conditions'
    is_default: bool = False
    threat_categories: List[str] = None     # Categories of threats to block
    risk_threshold: str = "MEDIUM_RISK"     # Minimum risk level to trigger

@dataclass
class ScanResult:
    """Complete logic bomb scan result"""
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
    threat_shield_status: str  # Changed from quality_gate_status
    logic_bomb_risk_score: float = 0.0  # NEW: Specialized risk score
    threat_intelligence: Dict[str, Any] = None  # NEW: Threat analysis

class LogicBombRulesEngine:
    """Manages logic bomb detection rules"""
    
    def __init__(self, rules_file: str = "logic_bomb_rules.json"):
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
            self._create_default_logic_bomb_rules()
    
    def _create_default_logic_bomb_rules(self):
        """Create default logic bomb detection rules"""
        default_rules = [
            SecurityRule(
                id="logic-bomb-time-trigger",
                name="Time-Based Logic Bomb",
                description="Detects suspicious time-based conditional execution that may trigger malicious actions on specific dates",
                severity="CRITICAL_BOMB",
                type="SCHEDULED_THREAT",
                language="*",
                pattern=r'if.*(?:date|datetime|time).*[><=].*\d{4}.*:.*(?:delete|remove|destroy|format|kill|rmdir|unlink)',
                remediation_effort=90,
                tags=["logic-bomb", "time-trigger", "malicious-code", "date-based"],
                threat_category="SCHEDULED_THREAT"
            ),
            SecurityRule(
                id="logic-bomb-user-targeted",
                name="User-Targeted Logic Bomb", 
                description="Detects malicious code that targets specific users for harmful actions",
                severity="CRITICAL_BOMB",
                type="TARGETED_ATTACK",
                language="*", 
                pattern=r'if.*(?:user|username|getuser|USER).*==.*["\'][^"\']*["\'].*:.*(?:delete|remove|destroy|corrupt|kill)',
                remediation_effort=75,
                tags=["logic-bomb", "user-targeted", "malicious-code", "personalized-attack"],
                threat_category="TARGETED_ATTACK"
            ),
            SecurityRule(
                id="logic-bomb-execution-counter",
                name="Counter-Based Logic Bomb",
                description="Detects execution count-based triggers that activate malicious behavior after N executions", 
                severity="HIGH_RISK",
                type="EXECUTION_TRIGGER",
                language="*",
                pattern=r'(?:count|counter|iteration|exec_count).*[><=].*\d+.*:.*(?:delete|remove|destroy|corrupt|format)',
                remediation_effort=60,
                tags=["logic-bomb", "counter-based", "trigger-condition", "execution-based"],
                threat_category="EXECUTION_TRIGGER"
            ),
            SecurityRule(
                id="logic-bomb-environment-condition",
                name="Environment-Based Logic Bomb",
                description="Detects environment-specific triggers that activate malicious behavior on target systems",
                severity="HIGH_RISK", 
                type="LOGIC_BOMB",
                language="*",
                pattern=r'if.*(?:env|environment|hostname|platform|gethostname).*==.*["\'][^"\']*["\'].*:.*(?:sys\.|os\.|subprocess|system)',
                remediation_effort=50,
                tags=["logic-bomb", "environment-trigger", "system-specific", "conditional-attack"],
                threat_category="SYSTEM_SPECIFIC_THREAT"
            ),
            SecurityRule(
                id="destructive-payload-detector",
                name="Destructive Payload Detection",
                description="Detects potentially destructive operations that could be payloads of logic bombs",
                severity="CRITICAL_BOMB",
                type="DESTRUCTIVE_PAYLOAD", 
                language="*",
                pattern=r'(?:shutil\.rmtree|os\.remove|subprocess\.call.*rm|system.*(?:del|rm)|format.*c:|rmdir.*\/s)',
                remediation_effort=120,
                tags=["destructive-payload", "system-damage", "malicious-code", "data-destruction"],
                threat_category="DESTRUCTIVE_PAYLOAD"
            ),
            SecurityRule(
                id="logic-bomb-network-trigger",
                name="Network-Based Logic Bomb",
                description="Detects network condition-based triggers for malicious activation",
                severity="MEDIUM_RISK",
                type="LOGIC_BOMB",
                language="*", 
                pattern=r'if.*(?:ping|connect|socket|urllib).*(?:fail|error|timeout).*:.*(?:delete|remove|destroy)',
                remediation_effort=45,
                tags=["logic-bomb", "network-trigger", "connectivity-based"],
                threat_category="CONNECTION_BASED_THREAT"
            ),
            SecurityRule(
                id="logic-bomb-file-existence",
                name="File-Based Logic Bomb Trigger",
                description="Detects file existence checks that may trigger malicious behavior",
                severity="MEDIUM_RISK",
                type="LOGIC_BOMB",
                language="*",
                pattern=r'if.*(?:not\s+)?(?:os\.path\.exists|pathlib\.Path\.exists).*:.*(?:delete|remove|destroy|corrupt)',
                remediation_effort=30,
                tags=["logic-bomb", "file-trigger", "existence-check"],
                threat_category="FILE_BOMB"
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
        """Add a new logic bomb detection rule"""
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

class ThreatShieldManager:
    """Manages threat protection shields (replaces QualityGateManager)"""
    
    def __init__(self, shields_file: str = "threat_shields.json"):
        self.shields_file = shields_file
        self.shields: Dict[str, ThreatShield] = {}
        self.load_shields()
    
    def load_shields(self):
        """Load threat shields from file"""
        if os.path.exists(self.shields_file):
            try:
                with open(self.shields_file, 'r') as f:
                    shields_data = json.load(f)
                    for shield_data in shields_data:
                        shield = ThreatShield(**shield_data)
                        self.shields[shield.id] = shield
            except Exception as e:
                print(f"Error loading threat shields: {e}")
        else:
            self._create_default_shields()
    
    def _create_default_shields(self):
        """Create default threat protection shields"""
        default_shield = ThreatShield(
            id="logic-bomb-protection-shield",
            name="Logic Bomb Protection Shield",
            is_default=True,
            risk_threshold="MEDIUM_RISK",
            threat_categories=["SCHEDULED_THREAT", "TARGETED_ATTACK", "EXECUTION_TRIGGER", "DESTRUCTIVE_PAYLOAD"],
            protection_rules=[
                {"threat_type": "SCHEDULED_THREAT", "risk_threshold": "HIGH_RISK", "block": True, "alert": True},
                {"threat_type": "TARGETED_ATTACK", "risk_threshold": "CRITICAL_BOMB", "block": True, "alert": True}, 
                {"threat_type": "EXECUTION_TRIGGER", "risk_threshold": "HIGH_RISK", "block": True, "alert": True},
                {"threat_type": "DESTRUCTIVE_PAYLOAD", "risk_threshold": "CRITICAL_BOMB", "block": True, "alert": True},
                {"threat_type": "SYSTEM_SPECIFIC_THREAT", "risk_threshold": "MEDIUM_RISK", "block": False, "alert": True},
                {"threat_type": "CONNECTION_BASED_THREAT", "risk_threshold": "MEDIUM_RISK", "block": False, "alert": True},
                {"threat_type": "FILE_BOMB", "risk_threshold": "MEDIUM_RISK", "block": False, "alert": True}
            ]
        )
        
        self.shields[default_shield.id] = default_shield
        self.save_shields()
    
    def save_shields(self):
        """Save threat shields to file"""
        try:
            shields_data = [asdict(shield) for shield in self.shields.values()]
            with open(self.shields_file, 'w') as f:
                json.dump(shields_data, f, indent=2)
        except Exception as e:
            print(f"Error saving threat shields: {e}")
    
    def evaluate_shield(self, shield_id: str, threat_metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate threat shield against detected threats"""
        if shield_id not in self.shields:
            return {"status": "ERROR", "message": "Threat shield not found"}
        
        shield = self.shields[shield_id]
        results = []
        overall_status = "PROTECTED"
        
        for rule in shield.protection_rules:
            threat_count = threat_metrics.get(rule["threat_type"], 0)
            risk_threshold = rule["risk_threshold"]
            should_block = rule.get("block", False)
            
            # Determine if threshold is exceeded
            risk_levels = {"SUSPICIOUS": 1, "LOW_RISK": 2, "MEDIUM_RISK": 3, "HIGH_RISK": 4, "CRITICAL_BOMB": 5}
            threshold_level = risk_levels.get(risk_threshold, 3)
            
            # Check if any threats exceed threshold
            threat_exceeded = threat_count > 0 and threshold_level <= 3  # Simplified logic
            
            rule_result = {
                "threat_type": rule["threat_type"],
                "threshold": risk_threshold,
                "detected_count": threat_count,
                "threshold_exceeded": threat_exceeded,
                "should_block": should_block,
                "should_alert": rule.get("alert", False)
            }
            
            results.append(rule_result)
            
            if threat_exceeded:
                if should_block:
                    overall_status = "BLOCKED"
                elif overall_status == "PROTECTED":
                    overall_status = "ALERT"
        
        return {
            "status": overall_status,
            "protection_rules": results,
            "shield_name": shield.name
        }

class ThreatIssueManager:
    """Manages logic bomb security issues and their lifecycle"""
    
    def __init__(self, issues_file: str = "threat_issues.json"):
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
        """Create a new logic bomb security issue"""
        issue_id = str(uuid.uuid4())
        current_time = datetime.now().isoformat()
        
        # Analyze trigger and payload
        trigger_analysis = self._analyze_trigger(code_snippet, issue_type)
        payload_analysis = self._analyze_payload(code_snippet, severity)
        
        issue = SecurityIssue(
            id=issue_id,
            rule_id=rule_id,
            file_path=file_path,
            line_number=line_number,
            column=column,
            message=message,
            severity=severity,
            type=issue_type,
            status="ACTIVE_THREAT",
            creation_date=current_time,
            update_date=current_time,
            code_snippet=code_snippet,
            suggested_fix=suggested_fix,
            threat_level=self._calculate_threat_level(severity, issue_type),
            trigger_analysis=trigger_analysis,
            payload_analysis=payload_analysis
        )
        
        self.issues[issue_id] = issue
        return issue
    
    def _analyze_trigger(self, code_snippet: str, issue_type: str) -> str:
        """Analyze what triggers this logic bomb"""
        trigger_patterns = {
            "SCHEDULED_THREAT": "Triggered by specific date/time conditions",
            "TARGETED_ATTACK": "Triggered when specific user is detected",
            "EXECUTION_TRIGGER": "Triggered after N executions",
            "SYSTEM_SPECIFIC_THREAT": "Triggered on specific system environments",
            "DESTRUCTIVE_PAYLOAD": "Direct destructive action detected"
        }
        return trigger_patterns.get(issue_type, "Unknown trigger pattern")
    
    def _analyze_payload(self, code_snippet: str, severity: str) -> str:
        """Analyze potential damage from this logic bomb"""
        if "delete" in code_snippet or "remove" in code_snippet:
            return "File/directory deletion - Data loss risk"
        elif "format" in code_snippet:
            return "System formatting - Complete data destruction"
        elif "kill" in code_snippet or "terminate" in code_snippet:
            return "Process termination - System disruption"
        elif "corrupt" in code_snippet:
            return "Data corruption - Information integrity loss"
        else:
            return f"Unknown payload - {severity} level threat detected"
    
    def _calculate_threat_level(self, severity: str, issue_type: str) -> str:
        """Calculate overall threat level"""
        if severity == "CRITICAL_BOMB" or issue_type == "DESTRUCTIVE_PAYLOAD":
            return "EXTREME"
        elif severity == "HIGH_RISK":
            return "HIGH"
        elif severity == "MEDIUM_RISK":
            return "MEDIUM"
        else:
            return "LOW"
    
    def update_issue_status(self, issue_id: str, status: str, assignee: str = None):
        """Update issue status"""
        if issue_id in self.issues:
            self.issues[issue_id].status = status
            self.issues[issue_id].update_date = datetime.now().isoformat()
            if assignee:
                self.issues[issue_id].assignee = assignee
            self.save_issues()
    
    def get_active_threats(self) -> List[SecurityIssue]:
        """Get all active threat issues"""
        return [issue for issue in self.issues.values() if issue.status == "ACTIVE_THREAT"]
    
    def get_critical_bombs(self) -> List[SecurityIssue]:
        """Get critical logic bomb threats"""
        return [issue for issue in self.issues.values() 
                if issue.severity == "CRITICAL_BOMB" and issue.status == "ACTIVE_THREAT"]

class ThreatMetricsCalculator:
    """Calculates specialized threat intelligence metrics"""
    
    @staticmethod
    def calculate_logic_bomb_risk_score(issues: List[SecurityIssue]) -> float:
        """Calculate logic bomb risk score (0-100)"""
        if not issues:
            return 0.0
        
        risk_weights = {
            "CRITICAL_BOMB": 25,
            "HIGH_RISK": 15,
            "MEDIUM_RISK": 8,
            "LOW_RISK": 3,
            "SUSPICIOUS": 1
        }
        
        total_risk = sum(risk_weights.get(issue.severity, 0) for issue in issues)
        
        # Normalize to 0-100 scale
        max_possible_risk = len(issues) * 25  # If all were CRITICAL_BOMB
        normalized_score = min(100, (total_risk / max_possible_risk) * 100 if max_possible_risk > 0 else 0)
        
        return round(normalized_score, 1)
    
    @staticmethod
    def calculate_threat_intelligence(issues: List[SecurityIssue]) -> Dict[str, Any]:
        """Calculate comprehensive threat intelligence"""
        if not issues:
            return {"threat_level": "MINIMAL", "recommendations": ["No threats detected"]}
        
        # Count by threat type
        threat_types = {}
        for issue in issues:
            threat_types[issue.type] = threat_types.get(issue.type, 0) + 1
        
        # Determine overall threat level
        critical_count = len([i for i in issues if i.severity == "CRITICAL_BOMB"])
        high_count = len([i for i in issues if i.severity == "HIGH_RISK"])
        
        if critical_count > 0:
            threat_level = "CRITICAL"
        elif high_count > 2:
            threat_level = "HIGH" 
        elif high_count > 0:
            threat_level = "ELEVATED"
        else:
            threat_level = "MODERATE"
        
        # Generate recommendations
        recommendations = []
        if critical_count > 0:
            recommendations.append(f"URGENT: {critical_count} critical logic bombs detected - Immediate neutralization required")
        if "SCHEDULED_THREAT" in threat_types:
            recommendations.append(f"Time-based triggers detected - Review date/time conditions in {threat_types['SCHEDULED_THREAT']} locations")
        if "DESTRUCTIVE_PAYLOAD" in threat_types:
            recommendations.append(f"Destructive payloads found - High risk of data loss in {threat_types['DESTRUCTIVE_PAYLOAD']} locations")
        
        return {
            "threat_level": threat_level,
            "total_threats": len(issues),
            "critical_bombs": critical_count,
            "threat_distribution": threat_types,
            "recommendations": recommendations[:5]  # Top 5 recommendations
        }

class LogicBombDetector:
    """Main logic bomb detection system (replaces SecurityScanner)"""
    
    def __init__(self, data_dir: str = "threatguard_data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        
        # Initialize components with new names
        self.rules_engine = LogicBombRulesEngine(str(self.data_dir / "logic_bomb_rules.json"))
        self.threat_shields = ThreatShieldManager(str(self.data_dir / "threat_shields.json"))
        self.issue_manager = ThreatIssueManager(str(self.data_dir / "threat_issues.json"))
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
    
    def generate_neutralization_guide(self, issue: SecurityIssue, rule: SecurityRule) -> str:
        """Generate specific neutralization instructions for logic bombs"""
        neutralization_guides = {
            "logic-bomb-time-trigger": "Remove or modify date/time conditions. Consider using proper scheduling systems instead.",
            "logic-bomb-user-targeted": "Remove user-specific conditions. Implement proper user authentication if needed.",
            "logic-bomb-execution-counter": "Remove counter-based conditions. Use proper iteration limits if needed.",
            "logic-bomb-environment-condition": "Remove environment checks or replace with proper configuration management.",
            "destructive-payload-detector": "CRITICAL: Remove all destructive file operations. Implement proper data management.",
            "logic-bomb-network-trigger": "Replace network failure conditions with proper error handling.",
            "logic-bomb-file-existence": "Replace file existence triggers with proper file management logic."
        }
        
        return neutralization_guides.get(rule.id, "Review and remove suspicious conditional logic according to security best practices")
    
    def scan_project(self, project_path: str, project_id: str) -> ScanResult:
        """Scan a project for logic bombs and return results"""
        start_time = datetime.now()
        scan_id = str(uuid.uuid4())
        
        print(f"🔍 ThreatGuard Pro: Scanning for logic bombs in {project_path}")
        
        # Find all source files
        source_files = []
        for ext in ['.py', '.js', '.ts', '.java', '.cs', '.php', '.c', '.cpp', '.go', '.rb']:
            source_files.extend(list(Path(project_path).rglob(f'*{ext}')))
        
        issues = []
        lines_of_code = 0
        
        # Scan each file for logic bombs
        for file_path in source_files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    file_lines = len(content.splitlines())
                    lines_of_code += file_lines
                
                # Get language from file extension
                language = file_path.suffix[1:] if file_path.suffix else 'unknown'
                
                # Get applicable logic bomb detection rules
                applicable_rules = self.rules_engine.get_enabled_rules(language)
                
                # Scan file with each rule
                file_issues = self._scan_file_for_logic_bombs(
                    str(file_path), content, applicable_rules
                )
                issues.extend(file_issues)
                
            except Exception as e:
                print(f"Error scanning file {file_path}: {e}")
        
        # Calculate specialized threat metrics
        logic_bomb_risk_score = ThreatMetricsCalculator.calculate_logic_bomb_risk_score(issues)
        threat_intelligence = ThreatMetricsCalculator.calculate_threat_intelligence(issues)
        
        # Calculate standard metrics (simplified for logic bomb focus)
        security_rating = self._calculate_security_rating(issues)
        reliability_rating = "A"  # Simplified
        maintainability_rating = "B"  # Simplified
        
        # Evaluate threat shield
        threat_metrics = {
            "SCHEDULED_THREAT": len([i for i in issues if i.type == "SCHEDULED_THREAT"]),
            "TARGETED_ATTACK": len([i for i in issues if i.type == "TARGETED_ATTACK"]),
            "EXECUTION_TRIGGER": len([i for i in issues if i.type == "EXECUTION_TRIGGER"]),
            "DESTRUCTIVE_PAYLOAD": len([i for i in issues if i.type == "DESTRUCTIVE_PAYLOAD"]),
            "LOGIC_BOMB": len([i for i in issues if i.type == "LOGIC_BOMB"])
        }
        
        default_shield = next((s for s in self.threat_shields.shields.values() if s.is_default), None)
        threat_shield_status = "PROTECTED"
        if default_shield:
            shield_eval = self.threat_shields.evaluate_shield(default_shield.id, threat_metrics)
            threat_shield_status = shield_eval["status"]
        
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
            threat_shield_status=threat_shield_status,
            logic_bomb_risk_score=logic_bomb_risk_score,
            threat_intelligence=threat_intelligence
        )
        
        # Save to history
        self.scan_history.append(scan_result)
        self.save_scan_history()
        
        # Save issues to issue manager
        for issue in issues:
            self.issue_manager.issues[issue.id] = issue
        self.issue_manager.save_issues()
        
        print(f"✅ Scan completed: {len(issues)} threats detected, Risk Score: {logic_bomb_risk_score}")
        
        return scan_result
    
    def _scan_file_for_logic_bombs(self, file_path: str, content: str, 
                                  rules: List[SecurityRule]) -> List[SecurityIssue]:
        """Scan a file with logic bomb detection rules"""
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
                            suggested_fix=self.generate_neutralization_guide(None, rule)
                        )
                        issue.effort = rule.remediation_effort
                        issues.append(issue)
                        
            except re.error as e:
                print(f"Invalid regex pattern in rule {rule.id}: {e}")
        
        return issues
    
    def _calculate_security_rating(self, issues: List[SecurityIssue]) -> str:
        """Calculate security rating based on logic bomb threats"""
        critical_bombs = len([i for i in issues if i.severity == "CRITICAL_BOMB"])
        high_risks = len([i for i in issues if i.severity == "HIGH_RISK"])
        
        if critical_bombs > 0:
            return "F"  # Critical logic bombs present
        elif high_risks > 2:
            return "E"  # Multiple high-risk threats
        elif high_risks > 0:
            return "D"  # Some high-risk threats
        elif len(issues) > 5:
            return "C"  # Multiple minor threats
        elif len(issues) > 0:
            return "B"  # Few minor threats
        else:
            return "A"  # No threats detected
    
    def get_command_center_metrics(self, project_id: str = None) -> Dict[str, Any]:
        """Get command center metrics for display (replaces dashboard metrics)"""
        # Get latest scan for project or overall
        if project_id:
            project_scans = [s for s in self.scan_history if s.project_id == project_id]
            latest_scan = max(project_scans, key=lambda x: x.timestamp) if project_scans else None
        else:
            latest_scan = max(self.scan_history, key=lambda x: x.timestamp) if self.scan_history else None
        
        if not latest_scan:
            return {"error": "No scan data available"}
        
        # Calculate threat counts by severity
        threat_severity_counts = {}
        for severity in ["CRITICAL_BOMB", "HIGH_RISK", "MEDIUM_RISK", "LOW_RISK", "SUSPICIOUS"]:
            threat_severity_counts[severity] = len([i for i in latest_scan.issues if i.severity == severity])
        
        # Calculate threat counts by type
        threat_type_counts = {}
        for threat_type in ["SCHEDULED_THREAT", "TARGETED_ATTACK", "EXECUTION_TRIGGER", "DESTRUCTIVE_PAYLOAD", "LOGIC_BOMB"]:
            threat_type_counts[threat_type] = len([i for i in latest_scan.issues if i.type == threat_type])
        
        return {
            "scan_info": {
                "project_id": latest_scan.project_id,
                "scan_date": latest_scan.timestamp,
                "files_scanned": latest_scan.files_scanned,
                "lines_of_code": latest_scan.lines_of_code,
                "duration_ms": latest_scan.duration_ms
            },
            "threat_ratings": {
                "security": latest_scan.security_rating,
                "reliability": latest_scan.reliability_rating,
                "maintainability": latest_scan.maintainability_rating,
                "logic_bomb_risk_score": latest_scan.logic_bomb_risk_score
            },
            "threat_shield": {
                "status": latest_scan.threat_shield_status
            },
            "threats": {
                "total": len(latest_scan.issues),
                "by_severity": threat_severity_counts,
                "by_type": threat_type_counts,
                "critical_bombs": len([i for i in latest_scan.issues if i.severity == "CRITICAL_BOMB"]),
                "active_threats": len([i for i in latest_scan.issues if i.status == "ACTIVE_THREAT"])
            },
            "threat_intelligence": latest_scan.threat_intelligence,
            "metrics": {
                "coverage": latest_scan.coverage,
                "duplications": latest_scan.duplications,
                "technical_debt": sum(issue.effort for issue in latest_scan.issues)
            }
        }


if __name__ == "__main__":
    # Example usage
    print("🛡️ ThreatGuard Pro - Logic Bomb Detection System")
    print("=" * 60)
    
    detector = LogicBombDetector()
    
    # Scan current directory
    result = detector.scan_project(".", "test-project")
    
    print(f"\n📊 Scan Results:")
    print(f"Scan completed in {result.duration_ms}ms")
    print(f"Files scanned: {result.files_scanned}")
    print(f"Logic bomb threats found: {len(result.issues)}")
    print(f"Security rating: {result.security_rating}")
    print(f"Logic bomb risk score: {result.logic_bomb_risk_score}/100")
    print(f"Threat shield status: {result.threat_shield_status}")
    
    # Get command center metrics
    metrics = detector.get_command_center_metrics()
    print(f"\n🎯 Command Center Metrics:")
    print(f"Total threats: {metrics['threats']['total']}")
    print(f"Critical bombs: {metrics['threats']['critical_bombs']}")
    print(f"Threat level: {metrics['threat_intelligence']['threat_level']}")
    
    if metrics['threat_intelligence']['recommendations']:
        print(f"\n⚠️ Recommendations:")
        for rec in metrics['threat_intelligence']['recommendations']:
            print(f"  • {rec}")
