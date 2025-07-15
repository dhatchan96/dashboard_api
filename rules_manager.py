#!/usr/bin/env python3
"""
Enhanced Security Scanner - Advanced Rules Management System
Production-ready rule engine with validation, testing, and management
"""

import re
import json
import uuid
import os
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import yaml

class RuleSeverity(Enum):
    BLOCKER = "BLOCKER"
    CRITICAL = "CRITICAL" 
    MAJOR = "MAJOR"
    MINOR = "MINOR"
    INFO = "INFO"

class RuleType(Enum):
    VULNERABILITY = "VULNERABILITY"
    BUG = "BUG"
    CODE_SMELL = "CODE_SMELL"
    SECURITY_HOTSPOT = "SECURITY_HOTSPOT"

class RuleLanguage(Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    CSHARP = "csharp"
    PHP = "php"
    HTML = "html"
    ALL = "*"

@dataclass
class RuleMetadata:
    """Extended metadata for security rules"""
    created_by: str
    created_date: str
    modified_by: Optional[str] = None
    modified_date: Optional[str] = None
    version: str = "1.0"
    source: str = "custom"  # custom, built-in, imported
    category: str = "security"
    cwe_id: Optional[str] = None  # Common Weakness Enumeration ID
    owasp_category: Optional[str] = None
    compliance_standards: List[str] = None

@dataclass
class RuleCondition:
    """Advanced rule condition with multiple criteria"""
    pattern: str
    context: Optional[str] = None  # function, class, global
    file_pattern: Optional[str] = None  # file name pattern
    exclude_patterns: List[str] = None
    line_limit: Optional[int] = None  # max lines to check
    case_sensitive: bool = False
    multiline: bool = False

@dataclass
class RuleRemediation:
    """Detailed remediation information"""
    description: str
    examples: List[str] = None
    references: List[str] = None
    effort_minutes: int = 30
    difficulty: str = "MEDIUM"  # EASY, MEDIUM, HARD
    automated_fix: Optional[str] = None

@dataclass
class AdvancedSecurityRule:
    """Advanced security rule with comprehensive metadata"""
    id: str
    name: str
    description: str
    severity: RuleSeverity
    type: RuleType
    language: RuleLanguage
    conditions: List[RuleCondition]
    remediation: RuleRemediation
    metadata: RuleMetadata
    tags: List[str]
    enabled: bool = True
    test_cases: List[Dict[str, Any]] = None

class RuleValidator:
    """Validates security rules for correctness and effectiveness"""
    
    @staticmethod
    def validate_rule(rule: AdvancedSecurityRule) -> Tuple[bool, List[str]]:
        """Validate a security rule"""
        errors = []
        
        # Basic validation
        if not rule.id or not rule.id.strip():
            errors.append("Rule ID cannot be empty")
        
        if not rule.name or not rule.name.strip():
            errors.append("Rule name cannot be empty")
        
        if not rule.description or not rule.description.strip():
            errors.append("Rule description cannot be empty")
        
        if not rule.conditions:
            errors.append("Rule must have at least one condition")
        
        # Validate patterns
        for i, condition in enumerate(rule.conditions):
            try:
                re.compile(condition.pattern)
            except re.error as e:
                errors.append(f"Invalid regex pattern in condition {i+1}: {e}")
        
        # Validate metadata
        if not rule.metadata.created_by:
            errors.append("Created by field is required")
        
        # Validate remediation
        if not rule.remediation.description:
            errors.append("Remediation description is required")
        
        if rule.remediation.effort_minutes < 1:
            errors.append("Remediation effort must be at least 1 minute")
        
        return len(errors) == 0, errors
    
    @staticmethod
    def test_rule(rule: AdvancedSecurityRule, test_code: str) -> Dict[str, Any]:
        """Test a rule against sample code"""
        results = {
            'matches': [],
            'performance': {},
            'false_positives': 0,
            'true_positives': 0
        }
        
        start_time = datetime.now()
        
        lines = test_code.split('\n')
        for condition in rule.conditions:
            try:
                flags = 0
                if not condition.case_sensitive:
                    flags |= re.IGNORECASE
                if condition.multiline:
                    flags |= re.MULTILINE
                
                pattern = re.compile(condition.pattern, flags)
                
                for line_num, line in enumerate(lines, 1):
                    if condition.line_limit and line_num > condition.line_limit:
                        break
                    
                    matches = pattern.finditer(line)
                    for match in matches:
                        results['matches'].append({
                            'line': line_num,
                            'column': match.start() + 1,
                            'text': match.group(),
                            'full_line': line.strip()
                        })
                        
            except Exception as e:
                results['error'] = str(e)
        
        end_time = datetime.now()
        results['performance']['execution_time_ms'] = int((end_time - start_time).total_seconds() * 1000)
        
        return results

class RuleTemplate:
    """Template system for creating common rule patterns"""
    
    TEMPLATES = {
        'hardcoded_secret': {
            'name': 'Hardcoded Secret Detection',
            'description': 'Detects hardcoded passwords, API keys, and secrets',
            'severity': RuleSeverity.CRITICAL,
            'type': RuleType.VULNERABILITY,
            'pattern': r'(password|secret|key|token)\s*[=:]\s*["\'][^"\']{8,}["\']',
            'category': 'security',
            'owasp_category': 'A02:2021 – Cryptographic Failures',
            'cwe_id': 'CWE-798'
        },
        'sql_injection': {
            'name': 'SQL Injection Vulnerability',
            'description': 'Detects potential SQL injection vulnerabilities',
            'severity': RuleSeverity.CRITICAL,
            'type': RuleType.VULNERABILITY,
            'pattern': r'(execute|query)\s*\(\s*["\'].*%.*["\']',
            'category': 'security',
            'owasp_category': 'A03:2021 – Injection',
            'cwe_id': 'CWE-89'
        },
        'xss_vulnerability': {
            'name': 'Cross-Site Scripting (XSS)',
            'description': 'Detects potential XSS vulnerabilities',
            'severity': RuleSeverity.MAJOR,
            'type': RuleType.VULNERABILITY,
            'pattern': r'(innerHTML|outerHTML)\s*=.*\+',
            'category': 'security',
            'owasp_category': 'A03:2021 – Injection',
            'cwe_id': 'CWE-79'
        },
        'weak_crypto': {
            'name': 'Weak Cryptographic Algorithm',
            'description': 'Detects usage of weak cryptographic algorithms',
            'severity': RuleSeverity.MAJOR,
            'type': RuleType.VULNERABILITY,
            'pattern': r'\b(md5|sha1|des|rc4)\s*\(',
            'category': 'cryptography',
            'owasp_category': 'A02:2021 – Cryptographic Failures',
            'cwe_id': 'CWE-327'
        },
        'command_injection': {
            'name': 'Command Injection',
            'description': 'Detects potential command injection vulnerabilities',
            'severity': RuleSeverity.CRITICAL,
            'type': RuleType.VULNERABILITY,
            'pattern': r'(exec|system|eval)\s*\([^)]*\+',
            'category': 'security',
            'owasp_category': 'A03:2021 – Injection',
            'cwe_id': 'CWE-78'
        }
    }
    
    @classmethod
    def create_from_template(cls, template_name: str, rule_id: str, 
                           language: RuleLanguage, created_by: str,
                           custom_pattern: str = None) -> AdvancedSecurityRule:
        """Create a rule from a template"""
        if template_name not in cls.TEMPLATES:
            raise ValueError(f"Template '{template_name}' not found")
        
        template = cls.TEMPLATES[template_name]
        
        condition = RuleCondition(
            pattern=custom_pattern or template['pattern'],
            case_sensitive=False,
            multiline=False
        )
        
        remediation = RuleRemediation(
            description=f"Fix the {template['name'].lower()} vulnerability",
            effort_minutes=60,
            difficulty="MEDIUM"
        )
        
        metadata = RuleMetadata(
            created_by=created_by,
            created_date=datetime.now().isoformat(),
            source="template",
            category=template['category'],
            cwe_id=template.get('cwe_id'),
            owasp_category=template.get('owasp_category')
        )
        
        return AdvancedSecurityRule(
            id=rule_id,
            name=template['name'],
            description=template['description'],
            severity=template['severity'],
            type=template['type'],
            language=language,
            conditions=[condition],
            remediation=remediation,
            metadata=metadata,
            tags=[template['category'], 'template']
        )

class RuleImporter:
    """Import rules from various formats"""
    
    @staticmethod
    def import_from_sonarqube(sonar_rules_json: str) -> List[AdvancedSecurityRule]:
        """Import rules from SonarQube format"""
        rules = []
        data = json.loads(sonar_rules_json)
        
        for rule_data in data.get('rules', []):
            # Convert SonarQube rule to our format
            condition = RuleCondition(
                pattern=rule_data.get('pattern', ''),
                case_sensitive=False
            )
            
            remediation = RuleRemediation(
                description=rule_data.get('remediation', ''),
                effort_minutes=rule_data.get('remediationEffort', 30)
            )
            
            metadata = RuleMetadata(
                created_by="sonarqube_import",
                created_date=datetime.now().isoformat(),
                source="sonarqube",
                category=rule_data.get('type', 'security')
            )
            
            rule = AdvancedSecurityRule(
                id=rule_data['key'],
                name=rule_data['name'],
                description=rule_data.get('htmlDesc', ''),
                severity=RuleSeverity(rule_data.get('severity', 'MAJOR')),
                type=RuleType(rule_data.get('type', 'VULNERABILITY')),
                language=RuleLanguage(rule_data.get('lang', '*')),
                conditions=[condition],
                remediation=remediation,
                metadata=metadata,
                tags=rule_data.get('tags', [])
            )
            
            rules.append(rule)
        
        return rules
    
    @staticmethod
    def import_from_yaml(yaml_content: str) -> List[AdvancedSecurityRule]:
        """Import rules from YAML format"""
        rules = []
        data = yaml.safe_load(yaml_content)
        
        for rule_data in data.get('rules', []):
            conditions = []
            for cond_data in rule_data.get('conditions', []):
                condition = RuleCondition(
                    pattern=cond_data['pattern'],
                    context=cond_data.get('context'),
                    file_pattern=cond_data.get('file_pattern'),
                    exclude_patterns=cond_data.get('exclude_patterns', []),
                    case_sensitive=cond_data.get('case_sensitive', False),
                    multiline=cond_data.get('multiline', False)
                )
                conditions.append(condition)
            
            remediation_data = rule_data.get('remediation', {})
            remediation = RuleRemediation(
                description=remediation_data.get('description', ''),
                examples=remediation_data.get('examples', []),
                references=remediation_data.get('references', []),
                effort_minutes=remediation_data.get('effort_minutes', 30),
                difficulty=remediation_data.get('difficulty', 'MEDIUM'),
                automated_fix=remediation_data.get('automated_fix')
            )
            
            metadata_data = rule_data.get('metadata', {})
            metadata = RuleMetadata(
                created_by=metadata_data.get('created_by', 'yaml_import'),
                created_date=metadata_data.get('created_date', datetime.now().isoformat()),
                source=metadata_data.get('source', 'yaml'),
                category=metadata_data.get('category', 'security'),
                cwe_id=metadata_data.get('cwe_id'),
                owasp_category=metadata_data.get('owasp_category'),
                compliance_standards=metadata_data.get('compliance_standards', [])
            )
            
            rule = AdvancedSecurityRule(
                id=rule_data['id'],
                name=rule_data['name'],
                description=rule_data['description'],
                severity=RuleSeverity(rule_data['severity']),
                type=RuleType(rule_data['type']),
                language=RuleLanguage(rule_data['language']),
                conditions=conditions,
                remediation=remediation,
                metadata=metadata,
                tags=rule_data.get('tags', []),
                enabled=rule_data.get('enabled', True),
                test_cases=rule_data.get('test_cases', [])
            )
            
            rules.append(rule)
        
        return rules

class RuleExporter:
    """Export rules to various formats"""
    
    @staticmethod
    def export_to_yaml(rules: List[AdvancedSecurityRule]) -> str:
        """Export rules to YAML format"""
        export_data = {'rules': []}
        
        for rule in rules:
            rule_dict = {
                'id': rule.id,
                'name': rule.name,
                'description': rule.description,
                'severity': rule.severity.value,
                'type': rule.type.value,
                'language': rule.language.value,
                'enabled': rule.enabled,
                'tags': rule.tags,
                'conditions': [
                    {
                        'pattern': cond.pattern,
                        'context': cond.context,
                        'file_pattern': cond.file_pattern,
                        'exclude_patterns': cond.exclude_patterns or [],
                        'case_sensitive': cond.case_sensitive,
                        'multiline': cond.multiline
                    }
                    for cond in rule.conditions
                ],
                'remediation': {
                    'description': rule.remediation.description,
                    'examples': rule.remediation.examples or [],
                    'references': rule.remediation.references or [],
                    'effort_minutes': rule.remediation.effort_minutes,
                    'difficulty': rule.remediation.difficulty,
                    'automated_fix': rule.remediation.automated_fix
                },
                'metadata': {
                    'created_by': rule.metadata.created_by,
                    'created_date': rule.metadata.created_date,
                    'modified_by': rule.metadata.modified_by,
                    'modified_date': rule.metadata.modified_date,
                    'version': rule.metadata.version,
                    'source': rule.metadata.source,
                    'category': rule.metadata.category,
                    'cwe_id': rule.metadata.cwe_id,
                    'owasp_category': rule.metadata.owasp_category,
                    'compliance_standards': rule.metadata.compliance_standards or []
                },
                'test_cases': rule.test_cases or []
            }
            export_data['rules'].append(rule_dict)
        
        return yaml.dump(export_data, default_flow_style=False, indent=2)
    
    @staticmethod
    def export_to_sonarqube(rules: List[AdvancedSecurityRule]) -> str:
        """Export rules to SonarQube format"""
        export_data = {'rules': []}
        
        for rule in rules:
            # Map our severity to SonarQube severity
            severity_mapping = {
                RuleSeverity.BLOCKER: 'BLOCKER',
                RuleSeverity.CRITICAL: 'CRITICAL',
                RuleSeverity.MAJOR: 'MAJOR',
                RuleSeverity.MINOR: 'MINOR',
                RuleSeverity.INFO: 'INFO'
            }
            
            # Map our type to SonarQube type
            type_mapping = {
                RuleType.VULNERABILITY: 'VULNERABILITY',
                RuleType.BUG: 'BUG',
                RuleType.CODE_SMELL: 'CODE_SMELL',
                RuleType.SECURITY_HOTSPOT: 'SECURITY_HOTSPOT'
            }
            
            rule_dict = {
                'key': rule.id,
                'name': rule.name,
                'htmlDesc': rule.description,
                'severity': severity_mapping[rule.severity],
                'type': type_mapping[rule.type],
                'lang': rule.language.value if rule.language != RuleLanguage.ALL else None,
                'status': 'READY' if rule.enabled else 'DEPRECATED',
                'tags': rule.tags,
                'pattern': rule.conditions[0].pattern if rule.conditions else '',
                'remediation': rule.remediation.description,
                'remediationEffort': rule.remediation.effort_minutes,
                'params': []
            }
            
            export_data['rules'].append(rule_dict)
        
        return json.dumps(export_data, indent=2)

class AdvancedRulesEngine:
    """Advanced rules engine with comprehensive management capabilities"""
    
    def __init__(self, rules_file: str = "advanced_security_rules.json"):
        self.rules_file = rules_file
        self.rules: Dict[str, AdvancedSecurityRule] = {}
        self.rule_validator = RuleValidator()
        self.load_rules()
        self._initialize_default_rules()
    
    def load_rules(self):
        """Load rules from file"""
        if os.path.exists(self.rules_file):
            try:
                with open(self.rules_file, 'r') as f:
                    rules_data = json.load(f)
                    for rule_data in rules_data:
                        rule = self._dict_to_rule(rule_data)
                        self.rules[rule.id] = rule
            except Exception as e:
                print(f"Error loading rules: {e}")
    
    def save_rules(self):
        """Save rules to file"""
        try:
            rules_data = [self._rule_to_dict(rule) for rule in self.rules.values()]
            with open(self.rules_file, 'w') as f:
                json.dump(rules_data, f, indent=2)
        except Exception as e:
            print(f"Error saving rules: {e}")
    
    def _dict_to_rule(self, rule_dict: Dict[str, Any]) -> AdvancedSecurityRule:
        """Convert dictionary to AdvancedSecurityRule"""
        conditions = [
            RuleCondition(**cond_dict) for cond_dict in rule_dict.get('conditions', [])
        ]
        
        remediation = RuleRemediation(**rule_dict.get('remediation', {}))
        metadata = RuleMetadata(**rule_dict.get('metadata', {}))
        
        return AdvancedSecurityRule(
            id=rule_dict['id'],
            name=rule_dict['name'],
            description=rule_dict['description'],
            severity=RuleSeverity(rule_dict['severity']),
            type=RuleType(rule_dict['type']),
            language=RuleLanguage(rule_dict['language']),
            conditions=conditions,
            remediation=remediation,
            metadata=metadata,
            tags=rule_dict.get('tags', []),
            enabled=rule_dict.get('enabled', True),
            test_cases=rule_dict.get('test_cases', [])
        )
    
    def _rule_to_dict(self, rule: AdvancedSecurityRule) -> Dict[str, Any]:
        """Convert AdvancedSecurityRule to dictionary"""
        return {
            'id': rule.id,
            'name': rule.name,
            'description': rule.description,
            'severity': rule.severity.value,
            'type': rule.type.value,
            'language': rule.language.value,
            'conditions': [asdict(cond) for cond in rule.conditions],
            'remediation': asdict(rule.remediation),
            'metadata': asdict(rule.metadata),
            'tags': rule.tags,
            'enabled': rule.enabled,
            'test_cases': rule.test_cases or []
        }
    
    def _initialize_default_rules(self):
        """Initialize default security rules if none exist"""
        if not self.rules:
            # Create default rules from templates
            templates = [
                ('hardcoded_secret', 'python'),
                ('sql_injection', 'python'),
                ('xss_vulnerability', 'javascript'),
                ('weak_crypto', '*'),
                ('command_injection', '*')
            ]
            
            for template_name, language in templates:
                rule_id = f"default-{template_name}-{language}"
                try:
                    rule = RuleTemplate.create_from_template(
                        template_name, rule_id, RuleLanguage(language), "system"
                    )
                    self.add_rule(rule)
                except Exception as e:
                    print(f"Error creating default rule {rule_id}: {e}")
    
    def add_rule(self, rule: AdvancedSecurityRule) -> Tuple[bool, List[str]]:
        """Add a new rule with validation"""
        # Validate rule
        is_valid, errors = self.rule_validator.validate_rule(rule)
        if not is_valid:
            return False, errors
        
        # Check for duplicate ID
        if rule.id in self.rules:
            return False, ["Rule ID already exists"]
        
        # Update metadata
        rule.metadata.created_date = datetime.now().isoformat()
        
        self.rules[rule.id] = rule
        self.save_rules()
        return True, []
    
    def update_rule(self, rule_id: str, updates: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Update an existing rule"""
        if rule_id not in self.rules:
            return False, ["Rule not found"]
        
        rule = self.rules[rule_id]
        
        # Create updated rule
        updated_rule_dict = self._rule_to_dict(rule)
        updated_rule_dict.update(updates)
        
        # Update metadata
        updated_rule_dict['metadata']['modified_by'] = updates.get('modified_by', 'system')
        updated_rule_dict['metadata']['modified_date'] = datetime.now().isoformat()
        
        try:
            updated_rule = self._dict_to_rule(updated_rule_dict)
        except Exception as e:
            return False, [f"Invalid rule data: {e}"]
        
        # Validate updated rule
        is_valid, errors = self.rule_validator.validate_rule(updated_rule)
        if not is_valid:
            return False, errors
        
        self.rules[rule_id] = updated_rule
        self.save_rules()
        return True, []
    
    def delete_rule(self, rule_id: str) -> bool:
        """Delete a rule"""
        if rule_id in self.rules:
            del self.rules[rule_id]
            self.save_rules()
            return True
        return False
    
    def get_rules_by_language(self, language: RuleLanguage) -> List[AdvancedSecurityRule]:
        """Get rules for a specific language"""
        return [
            rule for rule in self.rules.values()
            if rule.enabled and (rule.language == language or rule.language == RuleLanguage.ALL)
        ]
    
    def get_rules_by_severity(self, severity: RuleSeverity) -> List[AdvancedSecurityRule]:
        """Get rules by severity level"""
        return [rule for rule in self.rules.values() if rule.severity == severity]
    
    def get_rules_by_category(self, category: str) -> List[AdvancedSecurityRule]:
        """Get rules by category"""
        return [
            rule for rule in self.rules.values()
            if rule.metadata.category == category
        ]
    
    def search_rules(self, query: str) -> List[AdvancedSecurityRule]:
        """Search rules by name, description, or tags"""
        query_lower = query.lower()
        results = []
        
        for rule in self.rules.values():
            if (query_lower in rule.name.lower() or
                query_lower in rule.description.lower() or
                any(query_lower in tag.lower() for tag in rule.tags)):
                results.append(rule)
        
        return results
    
    def test_rule(self, rule_id: str, test_code: str) -> Dict[str, Any]:
        """Test a rule against sample code"""
        if rule_id not in self.rules:
            return {'error': 'Rule not found'}
        
        rule = self.rules[rule_id]
        return self.rule_validator.test_rule(rule, test_code)
    
    def validate_all_rules(self) -> Dict[str, List[str]]:
        """Validate all rules and return any errors"""
        validation_results = {}
        
        for rule_id, rule in self.rules.items():
            is_valid, errors = self.rule_validator.validate_rule(rule)
            if not is_valid:
                validation_results[rule_id] = errors
        
        return validation_results
    
    def get_rule_statistics(self) -> Dict[str, Any]:
        """Get statistics about the rule set"""
        total_rules = len(self.rules)
        enabled_rules = len([r for r in self.rules.values() if r.enabled])
        
        # Count by severity
        severity_counts = {}
        for severity in RuleSeverity:
            severity_counts[severity.value] = len(self.get_rules_by_severity(severity))
        
        # Count by type
        type_counts = {}
        for rule_type in RuleType:
            type_counts[rule_type.value] = len([
                r for r in self.rules.values() if r.type == rule_type
            ])
        
        # Count by language
        language_counts = {}
        for language in RuleLanguage:
            language_counts[language.value] = len([
                r for r in self.rules.values() if r.language == language
            ])
        
        # Count by category
        category_counts = {}
        for rule in self.rules.values():
            category = rule.metadata.category
            category_counts[category] = category_counts.get(category, 0) + 1
        
        return {
            'total_rules': total_rules,
            'enabled_rules': enabled_rules,
            'disabled_rules': total_rules - enabled_rules,
            'by_severity': severity_counts,
            'by_type': type_counts,
            'by_language': language_counts,
            'by_category': category_counts,
            'custom_rules': len([r for r in self.rules.values() if r.metadata.source == 'custom']),
            'template_rules': len([r for r in self.rules.values() if r.metadata.source == 'template'])
        }
    
    def export_rules(self, format_type: str = 'yaml') -> str:
        """Export rules in specified format"""
        rules_list = list(self.rules.values())
        
        if format_type.lower() == 'yaml':
            return RuleExporter.export_to_yaml(rules_list)
        elif format_type.lower() == 'sonarqube':
            return RuleExporter.export_to_sonarqube(rules_list)
        else:
            # Default JSON export
            return json.dumps([self._rule_to_dict(rule) for rule in rules_list], indent=2)
    
    def import_rules(self, content: str, format_type: str = 'yaml') -> Tuple[int, List[str]]:
        """Import rules from various formats"""
        imported_count = 0
        errors = []
        
        try:
            if format_type.lower() == 'yaml':
                imported_rules = RuleImporter.import_from_yaml(content)
            elif format_type.lower() == 'sonarqube':
                imported_rules = RuleImporter.import_from_sonarqube(content)
            else:
                # JSON format
                rules_data = json.loads(content)
                imported_rules = [self._dict_to_rule(rule_dict) for rule_dict in rules_data]
            
            for rule in imported_rules:
                # Check if rule already exists
                if rule.id in self.rules:
                    errors.append(f"Rule {rule.id} already exists - skipping")
                    continue
                
                # Validate rule
                is_valid, validation_errors = self.rule_validator.validate_rule(rule)
                if not is_valid:
                    errors.append(f"Rule {rule.id} validation failed: {', '.join(validation_errors)}")
                    continue
                
                self.rules[rule.id] = rule
                imported_count += 1
            
            if imported_count > 0:
                self.save_rules()
            
        except Exception as e:
            errors.append(f"Import failed: {str(e)}")
        
        return imported_count, errors
    
    def create_rule_from_template(self, template_name: str, rule_id: str,
                                language: str, created_by: str,
                                custom_pattern: str = None) -> Tuple[bool, List[str]]:
        """Create a rule from a template"""
        try:
            rule = RuleTemplate.create_from_template(
                template_name, rule_id, RuleLanguage(language), created_by, custom_pattern
            )
            return self.add_rule(rule)
        except Exception as e:
            return False, [str(e)]

# Example usage and testing
if __name__ == "__main__":
    # Initialize the advanced rules engine
    engine = AdvancedRulesEngine()
    
    print("🔧 Advanced Security Rules Engine")
    print("=" * 50)
    
    # Display statistics
    stats = engine.get_rule_statistics()
    print(f"Total Rules: {stats['total_rules']}")
    print(f"Enabled Rules: {stats['enabled_rules']}")
    print(f"Rules by Severity: {stats['by_severity']}")
    print(f"Rules by Type: {stats['by_type']}")
    print(f"Rules by Language: {stats['by_language']}")
    
    # Test creating a custom rule
    print("\n📝 Creating custom rule...")
    
    custom_condition = RuleCondition(
        pattern=r'eval\s*\(',
        case_sensitive=False
    )
    
    custom_remediation = RuleRemediation(
        description="Replace eval() with safer alternatives",
        examples=["Use JSON.parse() for parsing JSON", "Use Function constructor for dynamic functions"],
        effort_minutes=15,
        difficulty="EASY"
    )
    
    custom_metadata = RuleMetadata(
        created_by="admin",
        created_date=datetime.now().isoformat(),
        source="custom",
        category="security",
        cwe_id="CWE-95"
    )
    
    custom_rule = AdvancedSecurityRule(
        id="custom-eval-usage",
        name="Dangerous eval() Usage",
        description="Detects usage of eval() function which can lead to code injection",
        severity=RuleSeverity.CRITICAL,
        type=RuleType.VULNERABILITY,
        language=RuleLanguage.JAVASCRIPT,
        conditions=[custom_condition],
        remediation=custom_remediation,
        metadata=custom_metadata,
        tags=["security", "injection", "javascript"]
    )
    
    success, errors = engine.add_rule(custom_rule)
    if success:
        print("✅ Custom rule created successfully!")
    else:
        print(f"❌ Failed to create rule: {errors}")
    
    # Test rule against sample code
    print("\n🧪 Testing rule...")
    test_code = """
function processData(input) {
    var result = eval(input);
    return result;
}
"""
    
    test_results = engine.test_rule("custom-eval-usage", test_code)
    print(f"Test Results: {len(test_results.get('matches', []))} matches found")
    for match in test_results.get('matches', []):
        print(f"  Line {match['line']}: {match['full_line']}")
    
    # Export rules
    print("\n📤 Exporting rules...")
    yaml_export = engine.export_rules('yaml')
    print(f"YAML export length: {len(yaml_export)} characters")
    
    print("\n✅ Advanced Rules Engine initialization complete!")