"""
Privacy Risk Analyzer (APRA) - A tool to analyze digital privacy risks
"""
import re
import sys
import os
from datetime import datetime
from typing import Dict, List, Optional, Tuple

class PrivacyScanner:
    """Base class for privacy scanning functionality"""
    
    def __init__(self):
        self.risk_score = 0
        self.findings = []
    
    def calculate_risk_score(self) -> int:
        """Calculate privacy risk score based on findings"""
        score = 0
        for finding in self.findings:
            if finding['severity'] == 'high':
                score += 30
            elif finding['severity'] == 'medium':
                score += 20
            else:
                score += 10
        return score

class EmailAnalyzer(PrivacyScanner):
    """Analyzes email-related privacy risks"""
    
    def __init__(self, email: str):
        super().__init__()
        self.email = email
        
    def analyze(self) -> Dict:
        """Analyze email for common privacy risks"""
        risks = []
        
        # Check common email patterns
        if re.match(r'^[a-zA-Z]+\.[a-zA-Z]+@', self.email):
            risks.append({
                'type': 'email_pattern',
                'severity': 'medium',
                'description': 'Email follows common firstname.lastname pattern, making it easier to guess'
            })
            
        # Check for common domains
        domain = self.email.split('@')[1].lower()
        common_domains = ['gmail.com', 'yahoo.com', 'hotmail.com']
        if domain in common_domains:
            risks.append({
                'type': 'common_domain',
                'severity': 'low',
                'description': 'Using a common email domain can make your address easier to target in broad attacks'
            })
            
        # Check email length
        if len(self.email.split('@')[0]) < 6:
            risks.append({
                'type': 'short_username',
                'severity': 'medium',
                'description': 'Short email usernames are easier to guess or brute force'
            })
            
        # Check for numbers in email
        if re.search(r'\d+', self.email):
            risks.append({
                'type': 'numbers_in_email',
                'severity': 'low',
                'description': 'Numbers in email might indicate birth year or other personal information'
            })
            
        self.findings.extend(risks)
        return {
            'email': self.email,
            'risks': risks,
            'risk_score': self.calculate_risk_score()
        }

class PrivacySettingsAnalyzer(PrivacyScanner):
    """Analyzes privacy settings and provides recommendations"""
    
    def analyze_settings(self) -> Dict:
        """Analyze common privacy settings and provide recommendations"""
        risks = [
            {
                'type': 'password_manager',
                'severity': 'high',
                'description': 'Recommendation: Use a password manager for generating and storing strong, unique passwords',
                'action': 'Install a reputable password manager and create unique passwords for all accounts'
            },
            {
                'type': '2fa',
                'severity': 'high',
                'description': 'Enable two-factor authentication on all important accounts',
                'action': 'Set up 2FA using an authenticator app rather than SMS where possible'
            },
            {
                'type': 'privacy_checkup',
                'severity': 'medium',
                'description': 'Regular privacy checkups are recommended',
                'action': 'Review privacy settings on social media and important accounts monthly'
            }
        ]
        
        self.findings.extend(risks)
        return {
            'risks': risks,
            'risk_score': self.calculate_risk_score()
        }

class PrivacyReport:
    """Generates privacy analysis reports"""
    
    def __init__(self):
        self.timestamp = datetime.now()
        self.results = []
        
    def add_result(self, result: Dict):
        """Add analysis result to report"""
        self.results.append(result)
        
    def generate_text_report(self) -> str:
        """Generate a text-based report"""
        report = []
        report.append("Privacy Risk Analysis Report")
        report.append(f"Generated: {self.timestamp}")
        report.append("=" * 50)
        report.append("")
        
        total_risk_score = 0
        
        for result in self.results:
            if 'email' in result:
                report.append(f"Email Analysis for: {result['email']}")
                report.append("-" * 30)
            
            report.append("Identified Risks:")
            for risk in result.get('risks', []):
                report.append(f"\n▶ Risk Type: {risk['type'].replace('_', ' ').title()}")
                report.append(f"  Severity: {risk['severity'].upper()}")
                report.append(f"  Details: {risk['description']}")
                if 'action' in risk:
                    report.append(f"  Recommended Action: {risk['action']}")
            
            risk_score = result.get('risk_score', 0)
            total_risk_score += risk_score
            report.append(f"\nRisk Score: {risk_score}")
            report.append("\n" + "=" * 50 + "\n")
            
        report.append(f"Overall Risk Score: {total_risk_score}")
        
        if total_risk_score > 100:
            risk_level = "HIGH"
        elif total_risk_score > 50:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
            
        report.append(f"Risk Level: {risk_level}")
        return "\n".join(report)

class PrivacyAnalyzer:
    """Main class for coordinating privacy analysis"""
    
    def __init__(self):
        self.report = PrivacyReport()
        
    def analyze_email(self, email: str):
        """Analyze email privacy risks"""
        analyzer = EmailAnalyzer(email)
        result = analyzer.analyze()
        self.report.add_result(result)
        
    def analyze_privacy_settings(self):
        """Analyze privacy settings"""
        analyzer = PrivacySettingsAnalyzer()
        result = analyzer.analyze_settings()
        self.report.add_result(result)
        
    def generate_report(self) -> str:
        """Generate final analysis report"""
        return self.report.generate_text_report()

def validate_email(email: str) -> bool:
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def main():
    """Main function to run the privacy analyzer"""
    print("\nWelcome to the Privacy Risk Analyzer (APRA)")
    print("=" * 45)
    
    analyzer = PrivacyAnalyzer()
    
    while True:
        email = input("\nEnter email address to analyze: ").strip()
        if validate_email(email):
            break
        print("Invalid email format. Please try again.")
    
    print("\nAnalyzing privacy risks...")
    analyzer.analyze_email(email)
    
    print("Analyzing recommended privacy settings...")
    analyzer.analyze_privacy_settings()
    
    # Generate and display report
    print("\nGenerating Privacy Report...\n")
    print(analyzer.generate_report())

if __name__ == "__main__":
    main()
