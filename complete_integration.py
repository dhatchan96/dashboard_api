#!/usr/bin/env python3
"""
Enhanced Security Scanner - Complete Integration Script
Integrates all components: Scanner, Rules Engine, Dashboard API, and Leaderboard
Production-ready security scanning solution with SonarQube-equivalent features
"""

import os
import sys
import json
import shutil
from pathlib import Path
from datetime import datetime
import subprocess

# Component imports
try:
    from security_scanner_main import SecurityScanner, SecurityRule, QualityGate
    from dashboard_api import app as dashboard_app
    from rules_manager import AdvancedRulesEngine, RuleTemplate, RuleValidator
    from leaderboard_system import SecurityLeaderboard, SecurityScoreCalculator
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Make sure all component files are in the same directory:")
    print("  • security_scanner_main.py")
    print("  • dashboard_api.py")
    print("  • rules_manager.py")
    print("  • leaderboard_system.py")
    sys.exit(1)

class EnhancedSecurityScannerIntegration:
    """Complete integration of all security scanner components"""
    
    def __init__(self, base_dir: str = "security_scanner_workspace"):
        self.base_dir = Path(base_dir)
        self.setup_workspace()
        
        # Initialize all components
        print("🚀 Initializing Enhanced Security Scanner...")
        
        # Core scanner
        self.scanner = SecurityScanner(str(self.base_dir / "scanner_data"))
        
        # Advanced rules engine
        self.rules_engine = AdvancedRulesEngine(
            str(self.base_dir / "advanced_rules.json")
        )
        
        # Leaderboard system
        self.leaderboard = SecurityLeaderboard(
            str(self.base_dir / "leaderboard.json")
        )
        
        # Configuration
        self.config = self.load_config()
        
        print("✅ All components initialized successfully!")
    
    def setup_workspace(self):
        """Set up the workspace directory structure"""
        print(f"📁 Setting up workspace: {self.base_dir}")
        
        # Create main directories
        directories = [
            self.base_dir,
            self.base_dir / "scanner_data",
            self.base_dir / "reports",
            self.base_dir / "exports",
            self.base_dir / "imports",
            self.base_dir / "backups",
            self.base_dir / "temp"
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
        
        # Create default configuration
        self.create_default_config()
    
    def create_default_config(self):
        """Create default configuration file"""
        config_file = self.base_dir / "config.json"
        
        if not config_file.exists():
            default_config = {
                "scanner": {
                    "max_file_size_mb": 16,
                    "supported_extensions": [".py", ".js", ".ts", ".java", ".cs", ".php", ".html", ".json"],
                    "exclude_patterns": ["node_modules/", ".git/", "__pycache__/", "build/", "dist/"],
                    "parallel_processing": True,
                    "max_workers": 4
                },
                "rules": {
                    "auto_update": True,
                    "custom_rules_enabled": True,
                    "severity_threshold": "MINOR",
                    "rule_categories": ["security", "reliability", "maintainability"]
                },
                "quality_gates": {
                    "default_gate": "security-focused",
                    "auto_evaluation": True,
                    "fail_on_blocker": True,
                    "fail_on_critical": True
                },
                "leaderboard": {
                    "enabled": True,
                    "team_mode": True,
                    "history_retention_days": 90,
                    "auto_ranking": True
                },
                "dashboard": {
                    "host": "127.0.0.1",
                    "port": 5000,
                    "debug": False,
                    "auto_refresh_seconds": 30
                },
                "notifications": {
                    "email_enabled": False,
                    "slack_enabled": False,
                    "webhook_url": "",
                    "notify_on": ["scan_complete", "quality_gate_fail", "new_critical_issues"]
                },
                "exports": {
                    "auto_export": False,
                    "export_formats": ["json", "yaml", "csv"],
                    "export_schedule": "daily"
                }
            }
            
            with open(config_file, 'w') as f:
                json.dump(default_config, f, indent=2)
            
            print(f"📝 Created default configuration: {config_file}")
    
    def load_config(self) -> dict:
        """Load configuration from file"""
        config_file = self.base_dir / "config.json"
        
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"⚠️ Error loading config: {e}")
            return {}
    
    def scan_project_comprehensive(self, project_path: str, project_id: str, 
                                 team_name: str = None) -> dict:
        """Perform comprehensive project scan with all features"""
        print(f"\n🔍 Starting comprehensive scan for: {project_id}")
        print(f"📁 Project path: {project_path}")
        
        start_time = datetime.now()
        
        try:
            # 1. Core security scan
            print("  1️⃣ Running core security scan...")
            scan_result = self.scanner.scan_project(project_path, project_id)
            
            # 2. Advanced rules analysis
            print("  2️⃣ Running advanced rules analysis...")
            advanced_issues = self._run_advanced_rules_analysis(project_path, project_id)
            
            # 3. Quality gate evaluation
            print("  3️⃣ Evaluating quality gates...")
            quality_gate_result = self._evaluate_quality_gates(scan_result)
            
            # 4. Calculate technical debt
            print("  4️⃣ Calculating technical debt...")
            technical_debt = self._calculate_technical_debt(scan_result.issues)
            
            # 5. Update leaderboard
            print("  5️⃣ Updating leaderboard...")
            leaderboard_data = self._prepare_leaderboard_data(
                scan_result, technical_debt, team_name
            )
            self.leaderboard.update_project_metrics(leaderboard_data)
            
            # 6. Generate comprehensive report
            print("  6️⃣ Generating comprehensive report...")
            report = self._generate_comprehensive_report(
                scan_result, advanced_issues, quality_gate_result, 
                technical_debt, project_path
            )
            
            # 7. Save report
            self._save_report(report, project_id)
            
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            print(f"✅ Comprehensive scan completed in {duration:.2f} seconds")
            print(f"📊 Found {len(scan_result.issues)} total issues")
            print(f"🎯 Quality gate: {quality_gate_result['status']}")
            print(f"💰 Technical debt: {technical_debt:.1f} hours")
            
            return report
            
        except Exception as e:
            print(f"❌ Scan failed: {str(e)}")
            return {'error': str(e), 'project_id': project_id}
    
    def _run_advanced_rules_analysis(self, project_path: str, project_id: str) -> list:
        """Run advanced rules analysis"""
        advanced_issues = []
        
        # Get all source files
        source_files = []
        for ext in self.config.get('scanner', {}).get('supported_extensions', []):
            pattern = f"**/*{ext}"
            source_files.extend(Path(project_path).rglob(pattern))
        
        # Analyze each file with advanced rules
        for file_path in source_files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Detect language
                language = self._detect_file_language(str(file_path))
                
                # Get applicable advanced rules
                applicable_rules = self.rules_engine.get_rules_by_language(language)
                
                # Scan file with advanced rules
                for rule in applicable_rules:
                    if rule.enabled:
                        matches = self._scan_file_with_advanced_rule(
                            str(file_path), content, rule
                        )
                        advanced_issues.extend(matches)
                        
            except Exception as e:
                print(f"⚠️ Error analyzing {file_path}: {e}")
        
        return advanced_issues
    
    def _detect_file_language(self, file_path: str) -> str:
        """Detect programming language from file path"""
        ext = Path(file_path).suffix.lower()
        language_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.java': 'java',
            '.cs': 'csharp',
            '.php': 'php',
            '.html': 'html'
        }
        return language_map.get(ext, 'unknown')
    
    def _scan_file_with_advanced_rule(self, file_path: str, content: str, rule) -> list:
        """Scan file with an advanced rule"""
        import re
        
        issues = []
        lines = content.split('\n')
        
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
                    
                    # Check file pattern if specified
                    if condition.file_pattern:
                        if not re.search(condition.file_pattern, file_path):
                            continue
                    
                    # Check exclude patterns
                    if condition.exclude_patterns:
                        if any(re.search(excl, line) for excl in condition.exclude_patterns):
                            continue
                    
                    matches = pattern.finditer(line)
                    for match in matches:
                        issues.append({
                            'rule_id': rule.id,
                            'rule_name': rule.name,
                            'file_path': file_path,
                            'line_number': line_num,
                            'column': match.start() + 1,
                            'message': rule.description,
                            'severity': rule.severity.value,
                            'type': rule.type.value,
                            'code_snippet': line.strip(),
                            'suggested_fix': rule.remediation.description,
                            'cwe_id': rule.metadata.cwe_id,
                            'owasp_category': rule.metadata.owasp_category,
                            'effort_minutes': rule.remediation.effort_minutes
                        })
                        
            except re.error as e:
                print(f"⚠️ Invalid regex in rule {rule.id}: {e}")
        
        return issues
    
    def _evaluate_quality_gates(self, scan_result) -> dict:
        """Evaluate quality gates"""
        # Get default quality gate
        default_gate = None
        for gate in self.scanner.quality_gates.gates.values():
            if gate.is_default:
                default_gate = gate
                break
        
        if not default_gate:
            return {'status': 'NO_GATE', 'message': 'No quality gate configured'}
        
        # Prepare metrics for evaluation
        metrics = {
            'security_rating': ord(scan_result.security_rating) - ord('A') + 1,
            'reliability_rating': ord(scan_result.reliability_rating) - ord('A') + 1,
            'sqale_rating': ord(scan_result.maintainability_rating) - ord('A') + 1,
            'coverage': scan_result.coverage,
            'duplicated_lines_density': scan_result.duplications,
            'blocker_violations': len([i for i in scan_result.issues if i.severity == 'BLOCKER']),
            'critical_violations': len([i for i in scan_result.issues if i.severity == 'CRITICAL']),
            'major_violations': len([i for i in scan_result.issues if i.severity == 'MAJOR']),
            'minor_violations': len([i for i in scan_result.issues if i.severity == 'MINOR'])
        }
        
        return self.scanner.quality_gates.evaluate_gate(default_gate.id, metrics)
    
    def _calculate_technical_debt(self, issues: list) -> float:
        """Calculate technical debt in hours"""
        total_minutes = 0
        
        # Default effort by severity if not specified
        default_efforts = {
            'BLOCKER': 120,
            'CRITICAL': 60,
            'MAJOR': 30,
            'MINOR': 15,
            'INFO': 5
        }
        
        for issue in issues:
            effort = getattr(issue, 'effort', 0)
            if not effort:
                effort = default_efforts.get(issue.severity, 15)
            total_minutes += effort
        
        return total_minutes / 60  # Convert to hours
    
    def _prepare_leaderboard_data(self, scan_result, technical_debt: float, 
                                team_name: str = None) -> dict:
        """Prepare data for leaderboard update"""
        return {
            'project_id': scan_result.project_id,
            'project_name': scan_result.project_id,
            'timestamp': scan_result.timestamp,
            'security_rating': scan_result.security_rating,
            'reliability_rating': scan_result.reliability_rating,
            'maintainability_rating': scan_result.maintainability_rating,
            'quality_gate_status': scan_result.quality_gate_status,
            'coverage': scan_result.coverage,
            'duplications': scan_result.duplications,
            'technical_debt_hours': technical_debt,
            'lines_of_code': scan_result.lines_of_code,
            'files_scanned': scan_result.files_scanned,
            'duration_ms': scan_result.duration_ms,
            'issues': [
                {
                    'severity': issue.severity,
                    'type': issue.type
                }
                for issue in scan_result.issues
            ],
            'team_name': team_name
        }
    
    def _generate_comprehensive_report(self, scan_result, advanced_issues: list,
                                     quality_gate_result: dict, technical_debt: float,
                                     project_path: str) -> dict:
        """Generate comprehensive scan report"""
        
        # Combine all issues
        all_issues = []
        
        # Add core scanner issues
        for issue in scan_result.issues:
            all_issues.append({
                'id': issue.id,
                'rule_id': issue.rule_id,
                'file_path': issue.file_path,
                'line_number': issue.line_number,
                'column': issue.column,
                'message': issue.message,
                'severity': issue.severity,
                'type': issue.type,
                'status': issue.status,
                'code_snippet': issue.code_snippet,
                'suggested_fix': issue.suggested_fix,
                'source': 'core_scanner'
            })
        
        # Add advanced rules issues
        for issue in advanced_issues:
            all_issues.append({
                'id': f"adv_{hash(str(issue))}",
                'rule_id': issue['rule_id'],
                'file_path': issue['file_path'],
                'line_number': issue['line_number'],
                'column': issue['column'],
                'message': issue['message'],
                'severity': issue['severity'],
                'type': issue['type'],
                'status': 'OPEN',
                'code_snippet': issue['code_snippet'],
                'suggested_fix': issue['suggested_fix'],
                'cwe_id': issue.get('cwe_id'),
                'owasp_category': issue.get('owasp_category'),
                'effort_minutes': issue.get('effort_minutes'),
                'source': 'advanced_rules'
            })
        
        # Calculate statistics
        severity_counts = {}
        type_counts = {}
        for issue in all_issues:
            severity = issue['severity']
            issue_type = issue['type']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            type_counts[issue_type] = type_counts.get(issue_type, 0) + 1
        
        # Get project analytics from leaderboard
        project_analytics = self.leaderboard.get_project_analytics(scan_result.project_id)
        
        # Create comprehensive report
        report = {
            'scan_info': {
                'project_id': scan_result.project_id,
                'scan_id': scan_result.scan_id,
                'timestamp': scan_result.timestamp,
                'duration_ms': scan_result.duration_ms,
                'project_path': project_path,
                'scanner_version': '1.0.0'
            },
            'metrics': {
                'files_scanned': scan_result.files_scanned,
                'lines_of_code': scan_result.lines_of_code,
                'coverage': scan_result.coverage,
                'duplications': scan_result.duplications,
                'technical_debt_hours': technical_debt,
                'security_rating': scan_result.security_rating,
                'reliability_rating': scan_result.reliability_rating,
                'maintainability_rating': scan_result.maintainability_rating
            },
            'quality_gate': quality_gate_result,
            'issues': {
                'total': len(all_issues),
                'by_severity': severity_counts,
                'by_type': type_counts,
                'details': all_issues
            },
            'leaderboard': {
                'project_score': project_analytics.get('project_score', {}),
                'rank': project_analytics.get('project_score', {}).get('rank', 0),
                'recommendations': project_analytics.get('recommendations', [])
            },
            'summary': {
                'critical_issues_count': severity_counts.get('CRITICAL', 0) + severity_counts.get('BLOCKER', 0),
                'security_vulnerabilities': type_counts.get('VULNERABILITY', 0),
                'quality_gate_passed': quality_gate_result['status'] == 'OK',
                'needs_immediate_attention': severity_counts.get('BLOCKER', 0) > 0,
                'overall_health': self._calculate_overall_health(scan_result, technical_debt)
            }
        }
        
        return report
    
    def _calculate_overall_health(self, scan_result, technical_debt: float) -> str:
        """Calculate overall project health score"""
        score = 0
        
        # Rating scores
        rating_scores = {'A': 20, 'B': 15, 'C': 10, 'D': 5, 'E': 0}
        score += rating_scores.get(scan_result.security_rating, 0)
        score += rating_scores.get(scan_result.reliability_rating, 0)
        score += rating_scores.get(scan_result.maintainability_rating, 0)
        
        # Coverage bonus
        if scan_result.coverage >= 80:
            score += 20
        elif scan_result.coverage >= 60:
            score += 10
        
        # Quality gate bonus
        if scan_result.quality_gate_status == 'OK':
            score += 20
        
        # Technical debt penalty
        if technical_debt > 50:
            score -= 10
        elif technical_debt > 20:
            score -= 5
        
        # Issue count penalty
        blocker_count = len([i for i in scan_result.issues if i.severity == 'BLOCKER'])
        critical_count = len([i for i in scan_result.issues if i.severity == 'CRITICAL'])
        
        score -= blocker_count * 10
        score -= critical_count * 5
        
        # Determine health level
        if score >= 80:
            return "EXCELLENT"
        elif score >= 60:
            return "GOOD"
        elif score >= 40:
            return "FAIR"
        elif score >= 20:
            return "POOR"
        else:
            return "CRITICAL"
    
    def _save_report(self, report: dict, project_id: str):
        """Save comprehensive report to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = self.base_dir / "reports" / f"{project_id}_{timestamp}_comprehensive.json"
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"📄 Report saved: {report_file}")
    
    def start_dashboard_server(self):
        """Start the dashboard web server"""
        print("🌐 Starting dashboard server...")
        
        config = self.config.get('dashboard', {})
        host = config.get('host', '127.0.0.1')
        port = config.get('port', 5000)
        debug = config.get('debug', False)
        
        print(f"📍 Dashboard URL: http://{host}:{port}")
        print("🎯 Available endpoints:")
        print("  • /                     - Main dashboard")
        print("  • /api/dashboard/metrics - Dashboard metrics")
        print("  • /api/scan             - Start new scan")
        print("  • /api/issues           - Manage issues")
        print("  • /api/rules            - Manage rules")
        print("  • /api/leaderboard      - View rankings")
        
        # Update dashboard app with our integrated components
        dashboard_app.scanner = self.scanner
        dashboard_app.rules_engine = self.rules_engine
        dashboard_app.leaderboard = self.leaderboard
        
        try:
            dashboard_app.run(host=host, port=port, debug=debug)
        except KeyboardInterrupt:
            print("\n🛑 Dashboard server stopped")
    
    def export_all_data(self, format_type: str = 'json') -> str:
        """Export all scanner data"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        export_file = self.base_dir / "exports" / f"complete_export_{timestamp}.{format_type}"
        
        export_data = {
            'export_info': {
                'timestamp': datetime.now().isoformat(),
                'format': format_type,
                'components': ['scanner', 'rules', 'leaderboard']
            },
            'scanner_data': {
                'scan_history': [
                    {
                        'scan_id': scan.scan_id,
                        'project_id': scan.project_id,
                        'timestamp': scan.timestamp,
                        'metrics': {
                            'files_scanned': scan.files_scanned,
                            'lines_of_code': scan.lines_of_code,
                            'security_rating': scan.security_rating,
                            'quality_gate_status': scan.quality_gate_status
                        }
                    }
                    for scan in self.scanner.scan_history
                ],
                'issues_summary': {
                    'total_issues': len(self.scanner.issue_manager.issues),
                    'open_issues': len(self.scanner.issue_manager.get_open_issues())
                }
            },
            'rules_data': {
                'total_rules': len(self.rules_engine.rules),
                'enabled_rules': len([r for r in self.rules_engine.rules.values() if r.enabled]),
                'statistics': self.rules_engine.get_rule_statistics()
            },
            'leaderboard_data': self.leaderboard.get_leaderboard()
        }
        
        if format_type == 'yaml':
            import yaml
            content = yaml.dump(export_data, default_flow_style=False)
        else:
            content = json.dumps(export_data, indent=2)
        
        with open(export_file, 'w') as f:
            f.write(content)
        
        print(f"📤 Complete data exported to: {export_file}")
        return str(export_file)
    
    def backup_workspace(self) -> str:
        """Create a backup of the entire workspace"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"security_scanner_backup_{timestamp}"
        backup_path = self.base_dir / "backups" / backup_name
        
        # Create backup directory
        backup_path.mkdir(parents=True, exist_ok=True)
        
        # Copy all data files
        data_files = [
            "scanner_data",
            "advanced_rules.json",
            "leaderboard.json",
            "config.json"
        ]
        
        for item in data_files:
            source = self.base_dir / item
            if source.exists():
                if source.is_file():
                    shutil.copy2(source, backup_path)
                else:
                    shutil.copytree(source, backup_path / item)
        
        # Create backup archive
        archive_path = str(backup_path) + ".zip"
        shutil.make_archive(str(backup_path), 'zip', backup_path)
        
        # Clean up temporary directory
        shutil.rmtree(backup_path)
        
        print(f"💾 Workspace backed up to: {archive_path}")
        return archive_path
    
    def restore_workspace(self, backup_path: str):
        """Restore workspace from backup"""
        if not os.path.exists(backup_path):
            print(f"❌ Backup file not found: {backup_path}")
            return False
        
        print(f"🔄 Restoring workspace from: {backup_path}")
        
        # Extract backup
        temp_dir = self.base_dir / "temp" / "restore"
        shutil.rmtree(temp_dir, ignore_errors=True)
        shutil.unpack_archive(backup_path, temp_dir)
        
        # Copy files back
        for item in temp_dir.iterdir():
            target = self.base_dir / item.name
            if target.exists():
                if target.is_file():
                    target.unlink()
                else:
                    shutil.rmtree(target)
            
            if item.is_file():
                shutil.copy2(item, target)
            else:
                shutil.copytree(item, target)
        
        # Clean up
        shutil.rmtree(temp_dir)
        
        # Reload components
        self.__init__(str(self.base_dir))
        
        print("✅ Workspace restored successfully")
        return True
    
    def get_system_status(self) -> dict:
        """Get comprehensive system status"""
        return {
            'workspace': {
                'path': str(self.base_dir),
                'size_mb': sum(f.stat().st_size for f in self.base_dir.rglob('*') if f.is_file()) / (1024*1024)
            },
            'scanner': {
                'total_scans': len(self.scanner.scan_history),
                'total_issues': len(self.scanner.issue_manager.issues),
                'last_scan': self.scanner.scan_history[-1].timestamp if self.scanner.scan_history else None
            },
            'rules': {
                'total_rules': len(self.rules_engine.rules),
                'enabled_rules': len([r for r in self.rules_engine.rules.values() if r.enabled]),
                'custom_rules': len([r for r in self.rules_engine.rules.values() if r.metadata.source == 'custom'])
            },
            'leaderboard': {
                'total_projects': len(self.leaderboard.projects),
                'total_teams': len(self.leaderboard.teams)
            },
            'quality_gates': {
                'total_gates': len(self.scanner.quality_gates.gates),
                'default_gate': next((g.name for g in self.scanner.quality_gates.gates.values() if g.is_default), None)
            }
        }

def main():
    """Main entry point for the integrated security scanner"""
    print("🛡️ Enhanced Security Scanner - Complete Integration")
    print("=" * 70)
    
    # Initialize the integrated system
    scanner_system = EnhancedSecurityScannerIntegration()
    
    # Display system status
    status = scanner_system.get_system_status()
    print(f"\n📊 System Status:")
    print(f"  • Workspace: {status['workspace']['path']}")
    print(f"  • Total Scans: {status['scanner']['total_scans']}")
    print(f"  • Total Rules: {status['rules']['total_rules']} ({status['rules']['enabled_rules']} enabled)")
    print(f"  • Projects Tracked: {status['leaderboard']['total_projects']}")
    print(f"  • Quality Gates: {status['quality_gates']['total_gates']}")
    
    # Example usage
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == 'scan' and len(sys.argv) >= 4:
            project_path = sys.argv[2]
            project_id = sys.argv[3]
            team_name = sys.argv[4] if len(sys.argv) > 4 else None
            
            print(f"\n🎯 Scanning project: {project_id}")
            result = scanner_system.scan_project_comprehensive(project_path, project_id, team_name)
            
            if 'error' not in result:
                print(f"\n📈 Scan Results Summary:")
                print(f"  • Overall Health: {result['summary']['overall_health']}")
                print(f"  • Critical Issues: {result['summary']['critical_issues_count']}")
                print(f"  • Quality Gate: {'✅ PASSED' if result['summary']['quality_gate_passed'] else '❌ FAILED'}")
                print(f"  • Security Rating: {result['metrics']['security_rating']}")
                print(f"  • Technical Debt: {result['metrics']['technical_debt_hours']:.1f} hours")
        
        elif command == 'dashboard':
            scanner_system.start_dashboard_server()
        
        elif command == 'export':
            format_type = sys.argv[2] if len(sys.argv) > 2 else 'json'
            export_path = scanner_system.export_all_data(format_type)
            print(f"✅ Data exported to: {export_path}")
        
        elif command == 'backup':
            backup_path = scanner_system.backup_workspace()
            print(f"✅ Backup created: {backup_path}")
        
        elif command == 'status':
            status = scanner_system.get_system_status()
            print(f"\n📊 Detailed System Status:")
            print(json.dumps(status, indent=2))
        
        else:
            print(f"❌ Unknown command: {command}")
            print_usage()
    
    else:
        print_usage()

def print_usage():
    """Print usage instructions"""
    print(f"\n📚 Usage:")
    print(f"  python {sys.argv[0]} scan <project_path> <project_id> [team_name]")
    print(f"  python {sys.argv[0]} dashboard")
    print(f"  python {sys.argv[0]} export [json|yaml]")
    print(f"  python {sys.argv[0]} backup")
    print(f"  python {sys.argv[0]} status")
    print(f"\n💡 Examples:")
    print(f"  python {sys.argv[0]} scan ./my-project web-app-v1 frontend-team")
    print(f"  python {sys.argv[0]} dashboard")
    print(f"  python {sys.argv[0]} export yaml")

if __name__ == "__main__":
    main()
                