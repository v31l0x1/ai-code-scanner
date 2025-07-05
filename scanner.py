import os
import json
import logging
from typing import List, Dict, Optional
import google.generativeai as genai
# from google import genai
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class VulnerabilityScanner:
    """
    Core vulnerability scanner using OpenAI API to detect OWASP Top 10 vulnerabilities
    """
    
    def __init__(self, api_key: Optional[str] = None):
        api_key = api_key or os.getenv('GEMINI_API_KEY')
        if not api_key:
            raise ValueError("Gemini API key is required. Please set GEMINI_API_KEY environment variable.")
        
        try:
            genai.configure(api_key=api_key)
            self.model = genai.GenerativeModel('gemini-1.5-flash')
        except Exception as e:
            raise ValueError(f"Failed to initialize Gemini client: {str(e)}")
        
        self.logger = logging.getLogger(__name__)
        
        # OWASP Top 10 2021 categories
        self.owasp_categories = {
            'A01': 'A01:2021 – Broken Access Control',
            'A02': 'A02:2021 – Cryptographic Failures',
            'A03': 'A03:2021 – Injection',
            'A04': 'A04:2021 – Insecure Design',
            'A05': 'A05:2021 – Security Misconfiguration',
            'A06': 'A06:2021 – Vulnerable and Outdated Components',
            'A07': 'A07:2021 – Identification and Authentication Failures',
            'A08': 'A08:2021 – Software and Data Integrity Failures',
            'A09': 'A09:2021 – Security Logging and Monitoring Failures',
            'A10': 'A10:2021 – Server-Side Request Forgery (SSRF)'
        }
    
    def create_analysis_prompt(self, code: str, file_path: str = "") -> str:
        """Create a detailed prompt for vulnerability analysis"""
        return f"""
You are a cybersecurity expert specializing in code analysis. Analyze the following code for OWASP Top 10 2021 vulnerabilities.

Code to analyze:
```
{code}
```

File path: {file_path}

Please provide a detailed analysis in the following JSON format for each vulnerability found:

{{
  "vulnerabilities": [
    {{
      "severity": "Critical|High|Medium|Low",
      "description": "Detailed description of the vulnerability found",
      "recommendations": "Specific step-by-step recommendations to fix the vulnerability",
      "owasp_category": "A0X:2021 – Category Name",
      "line_number": line_number_if_applicable,
      "code_snippet": "specific vulnerable code snippet",
      "cwe_id": "CWE number if applicable"
    }}
  ]
}}

OWASP Top 10 2021 Categories to check:
- A01:2021 – Broken Access Control
- A02:2021 – Cryptographic Failures  
- A03:2021 – Injection
- A04:2021 – Insecure Design
- A05:2021 – Security Misconfiguration
- A06:2021 – Vulnerable and Outdated Components
- A07:2021 – Identification and Authentication Failures
- A08:2021 – Software and Data Integrity Failures
- A09:2021 – Security Logging and Monitoring Failures
- A10:2021 – Server-Side Request Forgery (SSRF)

Focus on:
1. SQL Injection vulnerabilities
2. Cross-site scripting (XSS)
3. Insecure direct object references
4. Security misconfigurations
5. Cryptographic issues
6. Authentication bypasses
7. Access control issues
8. Input validation problems
9. Logging and monitoring gaps
10. SSRF vulnerabilities

If no vulnerabilities are found, return: {{"vulnerabilities": []}}

Be thorough and provide actionable recommendations.
"""
    
    def analyze_code(self, code: str, file_path: str = "") -> Dict:
        """
        Analyze code for OWASP Top 10 vulnerabilities using Gemini API
        """
        try:
            prompt = self.create_analysis_prompt(code, file_path)
            
            response = self.model.generate_content(prompt)
            result = response.text
            
            # Parse JSON response
            try:
                analysis = json.loads(result)
                return analysis
            except json.JSONDecodeError:
                # If JSON parsing fails, try to extract JSON from the response
                import re
                json_match = re.search(r'\{.*\}', result, re.DOTALL)
                if json_match:
                    analysis = json.loads(json_match.group())
                    return analysis
                else:
                    return {"error": "Failed to parse AI response", "raw_response": result}
                    
        except Exception as e:
            self.logger.error(f"Error analyzing code: {str(e)}")
            return {"error": f"Analysis failed: {str(e)}"}
    
    def scan_file(self, file_path: str) -> Dict:
        """
        Scan a single file for vulnerabilities
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
            
            if not code.strip():
                return {"vulnerabilities": [], "message": "Empty file"}
            
            analysis = self.analyze_code(code, file_path)
            analysis['file_path'] = file_path
            return analysis
            
        except Exception as e:
            self.logger.error(f"Error scanning file {file_path}: {str(e)}")
            return {"error": f"Failed to scan file: {str(e)}", "file_path": file_path}
    
    def get_supported_extensions(self) -> List[str]:
        """
        Get list of supported file extensions
        """
        return [
            '.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.php', '.rb', '.go',
            '.cs', '.cpp', '.c', '.h', '.hpp', '.sql', '.html', '.xml', '.json',
            '.yaml', '.yml', '.sh', '.bash', '.ps1', '.jsp', '.asp', '.aspx'
        ]
    
    def should_scan_file(self, file_path: str) -> bool:
        """
        Check if file should be scanned based on extension
        """
        _, ext = os.path.splitext(file_path.lower())
        return ext in self.get_supported_extensions()
    
    def scan_directory(self, directory_path: str, recursive: bool = True) -> List[Dict]:
        """
        Scan all supported files in a directory
        """
        results = []
        
        try:
            if recursive:
                for root, dirs, files in os.walk(directory_path):
                    # Skip common non-source directories
                    dirs[:] = [d for d in dirs if d not in ['.git', '__pycache__', 'node_modules', '.venv', 'venv']]
                    
                    for file in files:
                        file_path = os.path.join(root, file)
                        if self.should_scan_file(file_path):
                            self.logger.info(f"Scanning: {file_path}")
                            result = self.scan_file(file_path)
                            results.append(result)
            else:
                for file in os.listdir(directory_path):
                    file_path = os.path.join(directory_path, file)
                    if os.path.isfile(file_path) and self.should_scan_file(file_path):
                        self.logger.info(f"Scanning: {file_path}")
                        result = self.scan_file(file_path)
                        results.append(result)
                        
        except Exception as e:
            self.logger.error(f"Error scanning directory {directory_path}: {str(e)}")
            results.append({"error": f"Failed to scan directory: {str(e)}"})
        
        return results
    
    def generate_report(self, results: List[Dict]) -> Dict:
        """
        Generate a comprehensive security report
        """
        total_files = len(results)
        total_vulnerabilities = 0
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        owasp_counts = {}
        
        for result in results:
            if 'vulnerabilities' in result:
                vulns = result['vulnerabilities']
                total_vulnerabilities += len(vulns)
                
                for vuln in vulns:
                    severity = vuln.get('severity', 'Unknown')
                    if severity in severity_counts:
                        severity_counts[severity] += 1
                    
                    owasp_cat = vuln.get('owasp_category', 'Unknown')
                    owasp_counts[owasp_cat] = owasp_counts.get(owasp_cat, 0) + 1
        
        return {
            "summary": {
                "total_files_scanned": total_files,
                "total_vulnerabilities": total_vulnerabilities,
                "severity_breakdown": severity_counts,
                "owasp_category_breakdown": owasp_counts
            },
            "detailed_results": results
        }
    
    def analyze_logs(self, log_content: str) -> Dict:
        """
        Analyze log files for security threats and anomalies
        """
        try:
            log_analysis_prompt = self.create_log_analysis_prompt(log_content)
            
            response = self.model.generate_content(log_analysis_prompt)
            
            if not response.text:
                return {"error": "No response from Gemini API"}
            
            # Parse the response
            return self.parse_log_analysis_response(response.text)
            
        except Exception as e:
            self.logger.error(f"Error analyzing logs: {str(e)}")
            return {"error": str(e)}

    def create_log_analysis_prompt(self, log_content: str) -> str:
        """Create a detailed prompt for log analysis"""
        return f"""
You are a cybersecurity expert specializing in log analysis. Analyze the following log content for security threats, anomalies, and potential attack patterns.

Log content to analyze:
```
{log_content}
```

Please analyze the logs and identify:
1. Failed login attempts and potential brute force attacks
2. Suspicious IP addresses or unusual access patterns
3. SQL injection attempts
4. XSS (Cross-Site Scripting) attempts
5. Command injection attempts
6. Unusual HTTP status codes or error patterns
7. Potential data exfiltration attempts
8. Anomalous traffic patterns
9. Authentication bypass attempts
10. Privilege escalation attempts

For each threat found, provide:
- Threat type and severity (Critical, High, Medium, Low)
- Description of the threat
- Specific log entries or patterns that indicate the threat
- Recommendations for mitigation
- Potential impact
- Indicators of compromise (IoCs) if applicable

Format your response as a JSON object with this structure:
{{
    "threats": [
        {{
            "threat_type": "string",
            "severity": "Critical|High|Medium|Low",
            "description": "string",
            "log_entries": ["string"],
            "recommendations": "string",
            "impact": "string",
            "iocs": ["string"]
        }}
    ],
    "summary": {{
        "total_threats": number,
        "critical_threats": number,
        "high_threats": number,
        "medium_threats": number,
        "low_threats": number,
        "analysis_date": "string"
    }}
}}

If no threats are found, return:
{{
    "threats": [],
    "summary": {{
        "total_threats": 0,
        "critical_threats": 0,
        "high_threats": 0,
        "medium_threats": 0,
        "low_threats": 0,
        "analysis_date": "string"
    }}
}}

Only return the JSON object, no other text.
"""

    def parse_log_analysis_response(self, response_text: str) -> Dict:
        """Parse the log analysis response from Gemini"""
        try:
            # Clean up the response text
            response_text = response_text.strip()
            
            # Remove markdown code blocks if present
            if response_text.startswith('```json'):
                response_text = response_text[7:]
            if response_text.startswith('```'):
                response_text = response_text[3:]
            if response_text.endswith('```'):
                response_text = response_text[:-3]
            
            # Parse JSON
            parsed_response = json.loads(response_text.strip())
            
            # Validate structure
            if 'threats' not in parsed_response:
                return {"error": "Invalid response format - missing 'threats' key"}
            
            return parsed_response
            
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse log analysis response: {str(e)}")
            return {"error": f"Failed to parse AI response: {str(e)}"}
        except Exception as e:
            self.logger.error(f"Error parsing log analysis response: {str(e)}")
            return {"error": str(e)}
