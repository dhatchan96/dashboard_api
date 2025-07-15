#!/usr/bin/env python3
"""
Enhanced Security Scanner - Leaderboard & Analytics System
Comprehensive scoring, ranking, and analytics for security metrics
"""

import json
import math
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import statistics

class MetricType(Enum):
    SECURITY_RATING = "security_rating"
    RELIABILITY_RATING = "reliability_rating"
    MAINTAINABILITY_RATING = "maintainability_rating"
    COVERAGE = "coverage"
    TECHNICAL_DEBT = "technical_debt"
    ISSUE_COUNT = "issue_count"
    QUALITY_GATE_STATUS = "quality_gate_status"

class TrendDirection(Enum):
    IMPROVING = "improving"
    DECLINING = "declining"
    STABLE = "stable"

@dataclass
class ProjectMetrics:
    """Project security and quality metrics"""
    project_id: str
    project_name: str
    last_scan_date: str
    security_rating: str  # A, B, C, D, E
    reliability_rating: str
    maintainability_rating: str
    quality_gate_status: str  # OK, WARN, ERROR
    total_issues: int
    blocker_issues: int
    critical_issues: int
    major_issues: int
    minor_issues: int
    info_issues: int
    coverage: float
    duplications: float
    technical_debt_hours: float
    lines_of_code: int
    files_scanned: int
    scan_duration_ms: int
    vulnerabilities: int
    bugs: int
    code_smells: int
    security_hotspots: int

@dataclass
class ProjectScore:
    """Calculated project score with components"""
    project_id: str
    total_score: float
    security_score: float
    reliability_score: float
    maintainability_score: float
    coverage_score: float
    quality_gate_score: float
    issue_penalty: float
    trend_bonus: float
    rank: int
    grade: str  # A+, A, B+, B, C+, C, D+, D, F

@dataclass
class TrendAnalysis:
    """Trend analysis for a project metric"""
    metric: str
    direction: TrendDirection
    change_percentage: float
    days_analyzed: int
    current_value: float
    previous_value: float
    volatility: float

@dataclass
class TeamMetrics:
    """Team-level aggregated metrics"""
    team_name: str
    projects: List[str]
    average_security_rating: float
    total_issues: int
    average_coverage: float
    total_technical_debt: float
    projects_with_quality_gate_ok: int
    team_score: float
    rank: int

class SecurityScoreCalculator:
    """Advanced security scoring algorithm"""
    
    # Base scores for ratings (A=100, B=80, C=60, D=40, E=20)
    RATING_SCORES = {
        'A': 100, 'B': 80, 'C': 60, 'D': 40, 'E': 20
    }
    
    # Weights for different components
    WEIGHTS = {
        'security': 0.35,      # 35% weight
        'reliability': 0.25,   # 25% weight
        'maintainability': 0.20, # 20% weight
        'coverage': 0.10,      # 10% weight
        'quality_gate': 0.10   # 10% weight
    }
    
    # Issue penalties (per issue)
    ISSUE_PENALTIES = {
        'BLOCKER': 10,
        'CRITICAL': 5,
        'MAJOR': 2,
        'MINOR': 0.5,
        'INFO': 0.1
    }
    
    @classmethod
    def calculate_project_score(cls, metrics: ProjectMetrics, 
                              trend_analysis: Optional[List[TrendAnalysis]] = None) -> ProjectScore:
        """Calculate comprehensive project score"""
        
        # Base component scores
        security_score = cls.RATING_SCORES.get(metrics.security_rating, 0)
        reliability_score = cls.RATING_SCORES.get(metrics.reliability_rating, 0)
        maintainability_score = cls.RATING_SCORES.get(metrics.maintainability_rating, 0)
        
        # Coverage score (0-100)
        coverage_score = min(100, metrics.coverage)
        
        # Quality gate score
        quality_gate_score = {
            'OK': 100,
            'WARN': 50,
            'ERROR': 0
        }.get(metrics.quality_gate_status, 0)
        
        # Calculate issue penalty
        issue_penalty = (
            metrics.blocker_issues * cls.ISSUE_PENALTIES['BLOCKER'] +
            metrics.critical_issues * cls.ISSUE_PENALTIES['CRITICAL'] +
            metrics.major_issues * cls.ISSUE_PENALTIES['MAJOR'] +
            metrics.minor_issues * cls.ISSUE_PENALTIES['MINOR'] +
            metrics.info_issues * cls.ISSUE_PENALTIES['INFO']
        )
        
        # Scale penalty based on project size
        if metrics.lines_of_code > 0:
            penalty_per_kloc = issue_penalty / (metrics.lines_of_code / 1000)
            scaled_penalty = min(50, penalty_per_kloc)  # Cap at 50 points
        else:
            scaled_penalty = issue_penalty
        
        # Calculate weighted score
        weighted_score = (
            security_score * cls.WEIGHTS['security'] +
            reliability_score * cls.WEIGHTS['reliability'] +
            maintainability_score * cls.WEIGHTS['maintainability'] +
            coverage_score * cls.WEIGHTS['coverage'] +
            quality_gate_score * cls.WEIGHTS['quality_gate']
        )
        
        # Apply issue penalty
        penalized_score = max(0, weighted_score - scaled_penalty)
        
        # Calculate trend bonus
        trend_bonus = cls._calculate_trend_bonus(trend_analysis) if trend_analysis else 0
        
        # Final score
        total_score = min(100, penalized_score + trend_bonus)
        
        # Determine grade
        grade = cls._score_to_grade(total_score)
        
        return ProjectScore(
            project_id=metrics.project_id,
            total_score=total_score,
            security_score=security_score,
            reliability_score=reliability_score,
            maintainability_score=maintainability_score,
            coverage_score=coverage_score,
            quality_gate_score=quality_gate_score,
            issue_penalty=scaled_penalty,
            trend_bonus=trend_bonus,
            rank=0,  # Will be set by leaderboard
            grade=grade
        )
    
    @classmethod
    def _calculate_trend_bonus(cls, trend_analysis: List[TrendAnalysis]) -> float:
        """Calculate bonus points for positive trends"""
        bonus = 0
        
        for trend in trend_analysis:
            if trend.direction == TrendDirection.IMPROVING:
                # Bonus based on improvement percentage
                improvement_bonus = min(5, abs(trend.change_percentage) / 10)
                bonus += improvement_bonus
            elif trend.direction == TrendDirection.DECLINING:
                # Penalty for declining trends
                decline_penalty = min(5, abs(trend.change_percentage) / 10)
                bonus -= decline_penalty
        
        return max(-10, min(10, bonus))  # Cap between -10 and +10
    
    @classmethod
    def _score_to_grade(cls, score: float) -> str:
        """Convert numerical score to letter grade"""
        if score >= 95:
            return "A+"
        elif score >= 90:
            return "A"
        elif score >= 85:
            return "B+"
        elif score >= 80:
            return "B"
        elif score >= 75:
            return "C+"
        elif score >= 70:
            return "C"
        elif score >= 65:
            return "D+"
        elif score >= 60:
            return "D"
        else:
            return "F"

class TrendAnalyzer:
    """Analyze trends in security metrics over time"""
    
    @staticmethod
    def analyze_metric_trend(values: List[Tuple[datetime, float]], 
                           metric_name: str) -> TrendAnalysis:
        """Analyze trend for a specific metric"""
        if len(values) < 2:
            return TrendAnalysis(
                metric=metric_name,
                direction=TrendDirection.STABLE,
                change_percentage=0,
                days_analyzed=0,
                current_value=values[0][1] if values else 0,
                previous_value=values[0][1] if values else 0,
                volatility=0
            )
        
        # Sort by date
        sorted_values = sorted(values, key=lambda x: x[0])
        
        # Calculate basic statistics
        current_value = sorted_values[-1][1]
        previous_value = sorted_values[0][1]
        days_analyzed = (sorted_values[-1][0] - sorted_values[0][0]).days
        
        # Calculate change percentage
        if previous_value != 0:
            change_percentage = ((current_value - previous_value) / previous_value) * 100
        else:
            change_percentage = 0
        
        # Determine trend direction
        if abs(change_percentage) < 5:  # Less than 5% change is considered stable
            direction = TrendDirection.STABLE
        elif change_percentage > 0:
            # For most metrics, higher is better, but for some it's worse
            if metric_name in ['technical_debt', 'issue_count', 'duplications']:
                direction = TrendDirection.DECLINING
            else:
                direction = TrendDirection.IMPROVING
        else:
            if metric_name in ['technical_debt', 'issue_count', 'duplications']:
                direction = TrendDirection.IMPROVING
            else:
                direction = TrendDirection.DECLINING
        
        # Calculate volatility (standard deviation of values)
        numeric_values = [v[1] for v in sorted_values]
        volatility = statistics.stdev(numeric_values) if len(numeric_values) > 1 else 0
        
        return TrendAnalysis(
            metric=metric_name,
            direction=direction,
            change_percentage=change_percentage,
            days_analyzed=days_analyzed,
            current_value=current_value,
            previous_value=previous_value,
            volatility=volatility
        )
    
    @staticmethod
    def analyze_all_trends(project_history: List[Dict[str, Any]]) -> List[TrendAnalysis]:
        """Analyze trends for all metrics of a project"""
        trends = []
        
        # Group data by metric
        metric_data = {}
        for scan in project_history:
            scan_date = datetime.fromisoformat(scan['timestamp'])
            
            # Extract metrics
            metrics = {
                'security_rating': TrendAnalyzer._rating_to_numeric(scan.get('security_rating', 'E')),
                'reliability_rating': TrendAnalyzer._rating_to_numeric(scan.get('reliability_rating', 'E')),
                'maintainability_rating': TrendAnalyzer._rating_to_numeric(scan.get('maintainability_rating', 'E')),
                'coverage': scan.get('coverage', 0),
                'technical_debt': scan.get('technical_debt_hours', 0),
                'issue_count': scan.get('total_issues', 0),
                'duplications': scan.get('duplications', 0)
            }
            
            for metric_name, value in metrics.items():
                if metric_name not in metric_data:
                    metric_data[metric_name] = []
                metric_data[metric_name].append((scan_date, value))
        
        # Analyze trend for each metric
        for metric_name, values in metric_data.items():
            if len(values) >= 2:
                trend = TrendAnalyzer.analyze_metric_trend(values, metric_name)
                trends.append(trend)
        
        return trends
    
    @staticmethod
    def _rating_to_numeric(rating: str) -> float:
        """Convert letter rating to numeric value for trend analysis"""
        rating_map = {'A': 5, 'B': 4, 'C': 3, 'D': 2, 'E': 1}
        return rating_map.get(rating, 1)

class SecurityLeaderboard:
    """Comprehensive security leaderboard and analytics system"""
    
    def __init__(self, data_file: str = "leaderboard_data.json"):
        self.data_file = data_file
        self.projects: Dict[str, ProjectMetrics] = {}
        self.teams: Dict[str, TeamMetrics] = {}
        self.project_history: Dict[str, List[Dict[str, Any]]] = {}
        self.calculator = SecurityScoreCalculator()
        self.trend_analyzer = TrendAnalyzer()
        self.load_data()
    
    def load_data(self):
        """Load leaderboard data from file"""
        try:
            if os.path.exists(self.data_file):
                with open(self.data_file, 'r') as f:
                    data = json.load(f)
                    
                # Load project metrics
                for proj_data in data.get('projects', []):
                    project = ProjectMetrics(**proj_data)
                    self.projects[project.project_id] = project
                
                # Load team metrics
                for team_data in data.get('teams', []):
                    team = TeamMetrics(**team_data)
                    self.teams[team.team_name] = team
                
                # Load project history
                self.project_history = data.get('project_history', {})
        
        except Exception as e:
            print(f"Error loading leaderboard data: {e}")
    
    def save_data(self):
        """Save leaderboard data to file"""
        try:
            data = {
                'projects': [asdict(project) for project in self.projects.values()],
                'teams': [asdict(team) for team in self.teams.values()],
                'project_history': self.project_history,
                'last_updated': datetime.now().isoformat()
            }
            
            with open(self.data_file, 'w') as f:
                json.dump(data, f, indent=2)
        
        except Exception as e:
            print(f"Error saving leaderboard data: {e}")
    
    def update_project_metrics(self, scan_result: Dict[str, Any]):
        """Update project metrics from a scan result"""
        project_id = scan_result['project_id']
        
        # Create/update project metrics
        project_metrics = ProjectMetrics(
            project_id=project_id,
            project_name=scan_result.get('project_name', project_id),
            last_scan_date=scan_result['timestamp'],
            security_rating=scan_result['security_rating'],
            reliability_rating=scan_result['reliability_rating'],
            maintainability_rating=scan_result['maintainability_rating'],
            quality_gate_status=scan_result['quality_gate_status'],
            total_issues=len(scan_result.get('issues', [])),
            blocker_issues=len([i for i in scan_result.get('issues', []) if i.get('severity') == 'BLOCKER']),
            critical_issues=len([i for i in scan_result.get('issues', []) if i.get('severity') == 'CRITICAL']),
            major_issues=len([i for i in scan_result.get('issues', []) if i.get('severity') == 'MAJOR']),
            minor_issues=len([i for i in scan_result.get('issues', []) if i.get('severity') == 'MINOR']),
            info_issues=len([i for i in scan_result.get('issues', []) if i.get('severity') == 'INFO']),
            coverage=scan_result.get('coverage', 0),
            duplications=scan_result.get('duplications', 0),
            technical_debt_hours=scan_result.get('technical_debt_hours', 0),
            lines_of_code=scan_result.get('lines_of_code', 0),
            files_scanned=scan_result.get('files_scanned', 0),
            scan_duration_ms=scan_result.get('duration_ms', 0),
            vulnerabilities=len([i for i in scan_result.get('issues', []) if i.get('type') == 'VULNERABILITY']),
            bugs=len([i for i in scan_result.get('issues', []) if i.get('type') == 'BUG']),
            code_smells=len([i for i in scan_result.get('issues', []) if i.get('type') == 'CODE_SMELL']),
            security_hotspots=len([i for i in scan_result.get('issues', []) if i.get('type') == 'SECURITY_HOTSPOT'])
        )
        
        self.projects[project_id] = project_metrics
        
        # Update project history
        if project_id not in self.project_history:
            self.project_history[project_id] = []
        
        # Add current scan to history
        history_entry = {
            'timestamp': scan_result['timestamp'],
            'security_rating': scan_result['security_rating'],
            'reliability_rating': scan_result['reliability_rating'],
            'maintainability_rating': scan_result['maintainability_rating'],
            'coverage': scan_result.get('coverage', 0),
            'technical_debt_hours': scan_result.get('technical_debt_hours', 0),
            'total_issues': len(scan_result.get('issues', [])),
            'duplications': scan_result.get('duplications', 0),
            'quality_gate_status': scan_result['quality_gate_status']
        }
        
        self.project_history[project_id].append(history_entry)
        
        # Keep only last 30 entries to prevent unlimited growth
        if len(self.project_history[project_id]) > 30:
            self.project_history[project_id] = self.project_history[project_id][-30:]
        
        self.save_data()
    
    def calculate_project_rankings(self) -> List[ProjectScore]:
        """Calculate and rank all projects"""
        project_scores = []
        
        for project in self.projects.values():
            # Get trend analysis for this project
            project_trends = None
            if project.project_id in self.project_history:
                project_trends = self.trend_analyzer.analyze_all_trends(
                    self.project_history[project.project_id]
                )
            
            # Calculate score
            score = self.calculator.calculate_project_score(project, project_trends)
            project_scores.append(score)
        
        # Sort by score (highest first) and assign ranks
        project_scores.sort(key=lambda x: x.total_score, reverse=True)
        for i, score in enumerate(project_scores, 1):
            score.rank = i
        
        return project_scores
    
    def get_leaderboard(self, limit: int = 50) -> Dict[str, Any]:
        """Get the complete leaderboard"""
        rankings = self.calculate_project_rankings()
        
        # Calculate summary statistics
        total_projects = len(rankings)
        average_score = statistics.mean([r.total_score for r in rankings]) if rankings else 0
        
        # Grade distribution
        grade_distribution = {}
        for score in rankings:
            grade_distribution[score.grade] = grade_distribution.get(score.grade, 0) + 1
        
        # Security rating distribution
        security_distribution = {}
        for project in self.projects.values():
            rating = project.security_rating
            security_distribution[rating] = security_distribution.get(rating, 0) + 1
        
        return {
            'rankings': rankings[:limit],
            'total_projects': total_projects,
            'average_score': round(average_score, 2),
            'grade_distribution': grade_distribution,
            'security_rating_distribution': security_distribution,
            'top_performers': rankings[:5],
            'needs_attention': [r for r in rankings if r.grade in ['D', 'F']][:5],
            'most_improved': self._get_most_improved_projects(),
            'statistics': {
                'total_issues': sum(p.total_issues for p in self.projects.values()),
                'total_vulnerabilities': sum(p.vulnerabilities for p in self.projects.values()),
                'total_technical_debt': sum(p.technical_debt_hours for p in self.projects.values()),
                'average_coverage': statistics.mean([p.coverage for p in self.projects.values()]) if self.projects else 0,
                'projects_with_quality_gate_ok': len([p for p in self.projects.values() if p.quality_gate_status == 'OK'])
            }
        }
    
    def _get_most_improved_projects(self) -> List[Dict[str, Any]]:
        """Get projects with the most improvement"""
        improvements = []
        
        for project_id, history in self.project_history.items():
            if len(history) >= 2:
                # Compare current vs 30 days ago
                current = history[-1]
                old = history[0]
                
                current_score = self._calculate_simple_score(current)
                old_score = self._calculate_simple_score(old)
                
                improvement = current_score - old_score
                if improvement > 0:
                    improvements.append({
                        'project_id': project_id,
                        'improvement': improvement,
                        'current_score': current_score,
                        'previous_score': old_score
                    })
        
        improvements.sort(key=lambda x: x['improvement'], reverse=True)
        return improvements[:5]
    
    def _calculate_simple_score(self, metrics: Dict[str, Any]) -> float:
        """Calculate a simple score for comparison"""
        rating_scores = {'A': 5, 'B': 4, 'C': 3, 'D': 2, 'E': 1}
        
        security_score = rating_scores.get(metrics.get('security_rating', 'E'), 1)
        reliability_score = rating_scores.get(metrics.get('reliability_rating', 'E'), 1)
        maintainability_score = rating_scores.get(metrics.get('maintainability_rating', 'E'), 1)
        coverage_score = metrics.get('coverage', 0) / 20  # Scale to 0-5
        
        return (security_score + reliability_score + maintainability_score + coverage_score) / 4
    
    def get_project_analytics(self, project_id: str) -> Dict[str, Any]:
        """Get detailed analytics for a specific project"""
        if project_id not in self.projects:
            return {'error': 'Project not found'}
        
        project = self.projects[project_id]
        history = self.project_history.get(project_id, [])
        
        # Calculate trends
        trends = self.trend_analyzer.analyze_all_trends(history) if len(history) >= 2 else []
        
        # Calculate score with trends
        project_score = self.calculator.calculate_project_score(project, trends)
        
        # Historical data for charts
        historical_data = {
            'security_ratings': [],
            'issue_counts': [],
            'coverage_values': [],
            'technical_debt': [],
            'scan_dates': []
        }
        
        for entry in history:
            historical_data['scan_dates'].append(entry['timestamp'])
            historical_data['security_ratings'].append(self.trend_analyzer._rating_to_numeric(entry['security_rating']))
            historical_data['issue_counts'].append(entry['total_issues'])
            historical_data['coverage_values'].append(entry['coverage'])
            historical_data['technical_debt'].append(entry.get('technical_debt_hours', 0))
        
        # Issue breakdown
        issue_breakdown = {
            'BLOCKER': project.blocker_issues,
            'CRITICAL': project.critical_issues,
            'MAJOR': project.major_issues,
            'MINOR': project.minor_issues,
            'INFO': project.info_issues
        }
        
        # Type breakdown
        type_breakdown = {
            'VULNERABILITY': project.vulnerabilities,
            'BUG': project.bugs,
            'CODE_SMELL': project.code_smells,
            'SECURITY_HOTSPOT': project.security_hotspots
        }
        
        # Find similar projects for benchmarking
        similar_projects = self._find_similar_projects(project)
        
        return {
            'project_metrics': asdict(project),
            'project_score': asdict(project_score),
            'trends': [asdict(trend) for trend in trends],
            'historical_data': historical_data,
            'issue_breakdown': issue_breakdown,
            'type_breakdown': type_breakdown,
            'similar_projects': similar_projects,
            'recommendations': self._generate_recommendations(project, trends)
        }
    
    def _find_similar_projects(self, target_project: ProjectMetrics, limit: int = 5) -> List[Dict[str, Any]]:
        """Find projects similar in size and characteristics"""
        similar = []
        target_loc = target_project.lines_of_code
        
        for project in self.projects.values():
            if project.project_id == target_project.project_id:
                continue
            
            # Calculate similarity based on lines of code (within 50% range)
            if target_loc > 0:
                size_ratio = project.lines_of_code / target_loc
                if 0.5 <= size_ratio <= 2.0:  # Within reasonable size range
                    similarity_score = 1 / (1 + abs(1 - size_ratio))  # Higher score for closer sizes
                    similar.append({
                        'project_id': project.project_id,
                        'project_name': project.project_name,
                        'lines_of_code': project.lines_of_code,
                        'security_rating': project.security_rating,
                        'similarity_score': similarity_score
                    })
        
        similar.sort(key=lambda x: x['similarity_score'], reverse=True)
        return similar[:limit]
    
    def _generate_recommendations(self, project: ProjectMetrics, trends: List[TrendAnalysis]) -> List[str]:
        """Generate improvement recommendations"""
        recommendations = []
        
        # Security rating recommendations
        if project.security_rating in ['D', 'E']:
            recommendations.append("🔴 Critical: Address security vulnerabilities immediately - focus on BLOCKER and CRITICAL issues")
        elif project.security_rating == 'C':
            recommendations.append("🟡 Review and fix security vulnerabilities to improve security rating")
        
        # Issue count recommendations
        if project.blocker_issues > 0:
            recommendations.append(f"🚨 Fix {project.blocker_issues} blocker issue(s) immediately")
        
        if project.critical_issues > 5:
            recommendations.append(f"⚠️ Reduce critical issues from {project.critical_issues} to under 5")
        
        # Coverage recommendations
        if project.coverage < 70:
            recommendations.append(f"📊 Increase test coverage from {project.coverage:.1f}% to at least 70%")
        elif project.coverage < 85:
            recommendations.append(f"📈 Consider increasing test coverage from {project.coverage:.1f}% to 85%+")
        
        # Technical debt recommendations
        debt_ratio = project.technical_debt_hours / (project.lines_of_code / 1000) if project.lines_of_code > 0 else 0
        if debt_ratio > 10:
            recommendations.append(f"💰 High technical debt: {project.technical_debt_hours:.1f} hours - prioritize refactoring")
        
        # Trend-based recommendations
        for trend in trends:
            if trend.direction == TrendDirection.DECLINING and trend.metric == 'security_rating':
                recommendations.append("📉 Security rating is declining - immediate attention needed")
            elif trend.direction == TrendDirection.DECLINING and trend.metric == 'coverage':
                recommendations.append("📉 Test coverage is declining - add more tests")
        
        # Quality gate recommendations
        if project.quality_gate_status == 'ERROR':
            recommendations.append("🚫 Quality gate failing - address all quality gate conditions")
        elif project.quality_gate_status == 'WARN':
            recommendations.append("⚠️ Quality gate warning - review and address warning conditions")
        
        if not recommendations:
            recommendations.append("✅ Project is performing well - maintain current quality standards")
        
        return recommendations[:10]  # Limit to top 10 recommendations
    
    def get_team_rankings(self) -> List[TeamMetrics]:
        """Calculate and return team rankings"""
        team_scores = []
        
        # Group projects by team (this would need team assignment logic)
        # For now, we'll create a simple team structure
        teams_data = {}
        
        for project in self.projects.values():
            # Simple team assignment based on project name prefix
            team_name = project.project_id.split('-')[0] if '-' in project.project_id else 'default'
            
            if team_name not in teams_data:
                teams_data[team_name] = {
                    'projects': [],
                    'security_ratings': [],
                    'coverages': [],
                    'total_issues': 0,
                    'total_technical_debt': 0,
                    'quality_gate_ok_count': 0
                }
            
            teams_data[team_name]['projects'].append(project.project_id)
            teams_data[team_name]['security_ratings'].append(self.trend_analyzer._rating_to_numeric(project.security_rating))
            teams_data[team_name]['coverages'].append(project.coverage)
            teams_data[team_name]['total_issues'] += project.total_issues
            teams_data[team_name]['total_technical_debt'] += project.technical_debt_hours
            
            if project.quality_gate_status == 'OK':
                teams_data[team_name]['quality_gate_ok_count'] += 1
        
        # Calculate team metrics
        for team_name, data in teams_data.items():
            avg_security = statistics.mean(data['security_ratings']) if data['security_ratings'] else 0
            avg_coverage = statistics.mean(data['coverages']) if data['coverages'] else 0
            
            # Calculate team score
            team_score = (
                avg_security * 20 +  # Max 100 points
                (avg_coverage / 100) * 30 +  # Max 30 points
                (data['quality_gate_ok_count'] / len(data['projects'])) * 50 if data['projects'] else 0  # Max 50 points
            )
            
            team_metrics = TeamMetrics(
                team_name=team_name,
                projects=data['projects'],
                average_security_rating=avg_security,
                total_issues=data['total_issues'],
                average_coverage=avg_coverage,
                total_technical_debt=data['total_technical_debt'],
                projects_with_quality_gate_ok=data['quality_gate_ok_count'],
                team_score=team_score,
                rank=0
            )
            
            team_scores.append(team_metrics)
        
        # Sort by score and assign ranks
        team_scores.sort(key=lambda x: x.team_score, reverse=True)
        for i, team in enumerate(team_scores, 1):
            team.rank = i
        
        # Update internal teams data
        self.teams = {team.team_name: team for team in team_scores}
        
        return team_scores

# Example usage and testing
if __name__ == "__main__":
    import os
    
    # Initialize leaderboard system
    leaderboard = SecurityLeaderboard()
    
    print("🏆 Security Leaderboard & Analytics System")
    print("=" * 60)
    
    # Example project data
    example_scan = {
        'project_id': 'web-app-frontend',
        'project_name': 'Web Application Frontend',
        'timestamp': datetime.now().isoformat(),
        'security_rating': 'B',
        'reliability_rating': 'A',
        'maintainability_rating': 'C',
        'quality_gate_status': 'OK',
        'coverage': 85.5,
        'duplications': 2.1,
        'technical_debt_hours': 12.5,
        'lines_of_code': 15000,
        'files_scanned': 125,
        'duration_ms': 45000,
        'issues': [
            {'severity': 'CRITICAL', 'type': 'VULNERABILITY'},
            {'severity': 'MAJOR', 'type': 'BUG'},
            {'severity': 'MAJOR', 'type': 'CODE_SMELL'},
            {'severity': 'MINOR', 'type': 'CODE_SMELL'},
            {'severity': 'MINOR', 'type': 'CODE_SMELL'}
        ]
    }
    
    # Update project metrics
    leaderboard.update_project_metrics(example_scan)
    
    # Add some historical data for trend analysis
    for i in range(5):
        historical_scan = example_scan.copy()
        historical_scan['timestamp'] = (datetime.now() - timedelta(days=i*7)).isoformat()
        historical_scan['coverage'] = 85.5 - i * 2  # Declining coverage
        historical_scan['technical_debt_hours'] = 12.5 + i * 1.5  # Increasing debt
        leaderboard.update_project_metrics(historical_scan)
    
    # Get leaderboard
    leaderboard_data = leaderboard.get_leaderboard()
    
    print(f"\n📊 Leaderboard Summary:")
    print(f"Total Projects: {leaderboard_data['total_projects']}")
    print(f"Average Score: {leaderboard_data['average_score']}")
    print(f"Projects with Quality Gate OK: {leaderboard_data['statistics']['projects_with_quality_gate_ok']}")
    
    print(f"\n🏅 Top Performers:")
    for i, project in enumerate(leaderboard_data['top_performers'], 1):
        print(f"  {i}. {project.project_id} - Score: {project.total_score:.1f} ({project.grade})")
    
    # Get detailed project analytics
    analytics = leaderboard.get_project_analytics('web-app-frontend')
    
    print(f"\n📈 Project Analytics for 'web-app-frontend':")
    print(f"Current Score: {analytics['project_score']['total_score']:.1f}")
    print(f"Grade: {analytics['project_score']['grade']}")
    print(f"Rank: {analytics['project_score']['rank']}")
    
    print(f"\n📋 Recommendations:")
    for rec in analytics['recommendations']:
        print(f"  • {rec}")
    
    print(f"\n📊 Trends Detected:")
    for trend in analytics['trends']:
        direction_emoji = {"improving": "📈", "declining": "📉", "stable": "➡️"}
        print(f"  {direction_emoji.get(trend['direction'], '➡️')} {trend['metric']}: "
              f"{trend['change_percentage']:.1f}% change")
    
    # Team rankings
    team_rankings = leaderboard.get_team_rankings()
    
    print(f"\n👥 Team Rankings:")
    for team in team_rankings:
        print(f"  {team.rank}. {team.team_name} - Score: {team.team_score:.1f}")
        print(f"     Projects: {len(team.projects)}, Avg Security: {team.average_security_rating:.1f}")
    
    print("\n✅ Leaderboard system initialized successfully!")