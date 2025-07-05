# AI Code Scanner

A modern, AI-powered security analysis tool that detects OWASP Top 10 vulnerabilities in code and analyzes log files for security threats. Built with a sleek, ChatGPT-inspired interface using a black and white theme.

## Features

### Code Analysis

- **OWASP Top 10 Detection**: Comprehensive analysis for all OWASP Top 10 2021 vulnerabilities
- **Multi-Language Support**: Supports Python, JavaScript, Java, PHP, C#, C++, SQL, HTML, and more
- **AI-Powered Analysis**: Uses Google Gemini AI for accurate vulnerability detection
- **Detailed Reports**: Provides severity levels, descriptions, and actionable recommendations

### Log Analysis (New!)

- **Security Threat Detection**: Identifies potential security threats in log files
- **Attack Pattern Recognition**: Detects brute force attacks, injection attempts, and anomalous patterns
- **Multi-Log Support**: Analyzes Apache, Nginx, Windows Event Logs, and custom log formats
- **IoC Identification**: Extracts Indicators of Compromise from log data

### Modern Interface

- **ChatGPT-Inspired Design**: Clean, modern interface similar to popular AI chat applications
- **Dark Theme**: Professional black and white color scheme
- **Responsive Design**: Works seamlessly on desktop and mobile devices
- **Tabbed Interface**: Easy switching between code analysis, file upload, and log analysis

## Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/ai-code-scanner.git
cd ai-code-scanner
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Set up environment variables:

```bash
# Create a .env file with your Google Gemini API key
GEMINI_API_KEY=your_gemini_api_key_here
```

4. Run the application:

```bash
python app.py
```

## Usage

### Code Analysis

1. Navigate to the application in your browser
2. Select the "Code Analysis" tab
3. Paste your code or upload a file
4. Click "Analyze Code" to get security insights

### Log Analysis

1. Select the "Log Analysis" tab
2. Paste your log content
3. Click "Analyze Logs" to detect security threats
4. Review detailed threat analysis and recommendations

## Supported File Types

### Code Files

- Python (.py)
- JavaScript (.js, .jsx)
- TypeScript (.ts, .tsx)
- Java (.java)
- PHP (.php)
- C# (.cs)
- C/C++ (.c, .cpp, .h, .hpp)
- SQL (.sql)
- HTML (.html)
- And many more...

### Log Files

- Apache Access/Error Logs
- Nginx Logs
- Windows Event Logs
- Application Logs
- System Logs
- Custom Log Formats (.log, .txt)

## OWASP Top 10 Coverage

Our tool detects all OWASP Top 10 2021 vulnerabilities:

1. **A01:2021** – Broken Access Control
2. **A02:2021** – Cryptographic Failures
3. **A03:2021** – Injection
4. **A04:2021** – Insecure Design
5. **A05:2021** – Security Misconfiguration
6. **A06:2021** – Vulnerable and Outdated Components
7. **A07:2021** – Identification and Authentication Failures
8. **A08:2021** – Software and Data Integrity Failures
9. **A09:2021** – Security Logging and Monitoring Failures
10. **A10:2021** – Server-Side Request Forgery (SSRF)

## Export Options

- **JSON Export**: Machine-readable format for integration
- **CSV Export**: Spreadsheet-compatible format
- **PDF Export**: Print-friendly reports

## Requirements

- Python 3.7+
- Flask
- Google Gemini API key
- Modern web browser

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

MIT License - see LICENSE file for details

## Security Notice

This tool is designed to help identify security vulnerabilities but should not be considered a complete security solution. Always follow secure coding practices and conduct thorough security testing.
