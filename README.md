<h1 align="center">AI Code Scanner</h1>

<p align="center">
  <img src="https://img.shields.io/badge/OWASP%20Top%2010-2021-blue" alt="OWASP Top 10">
  <img src="https://img.shields.io/badge/AI-Gemini-brightgreen" alt="AI Gemini">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="MIT License">
</p>

AI Code Scanner is a modern, AI-powered security analysis tool that detects OWASP Top 10 vulnerabilities in code and analyzes log files for security threats. It features a sleek, ChatGPT-inspired interface with a professional dark theme.

---

## 🚀 Features

### 🔒 Code & Log Analysis
- **OWASP Top 10 Detection:** Comprehensive analysis for all OWASP Top 10 2021 vulnerabilities
- **Multi-Language Support:** Python, JavaScript, Java, PHP, C#, C++, SQL, HTML, and more
- **AI-Powered:** Uses Google Gemini AI for accurate vulnerability detection
- **Detailed Reports:** Severity levels, descriptions, and actionable recommendations
- **Log Analysis:** Detects brute force, injection, privilege escalation, and more in logs

### 💻 Modern Interface
- **ChatGPT-Inspired:** Clean, modern, and responsive design
- **Tabbed UI:** Easy switching between code, file upload, and log analysis
- **Dark Theme:** Professional black and white color scheme

### 📦 Export Options
- **JSON, CSV, PDF:** Export results for integration, reporting, or sharing

---

## 🛠️ Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/ai-code-scanner.git
   cd ai-code-scanner
   ```
2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
3. **Set up environment variables:**
   - Create a `.env` file with your Google Gemini API key:
     ```env
     GEMINI_API_KEY=your_gemini_api_key_here
     SECRET_KEY=your_flask_secret_key
     ```
4. **Run the application:**
   ```bash
   python app.py
   ```

---

## 🧑‍💻 Usage

### Code Analysis
1. Open the app in your browser (default: http://localhost:5000)
2. Select the "Code Analysis" tab
3. Paste your code or upload a file
4. Click "Analyze Code" to get security insights

### Log Analysis
1. Select the "Log Analysis" tab
2. Paste your log content
3. Click "Analyze Logs" to detect security threats
4. Review detailed threat analysis and recommendations

---

## 📂 Supported File Types

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

---

## 🛡️ OWASP Top 10 Coverage

AI Code Scanner detects all OWASP Top 10 2021 vulnerabilities:

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

---

## 📤 Export Options
- **JSON:** Machine-readable format for integration
- **CSV:** Spreadsheet-compatible format
- **PDF:** Print-friendly reports

---

## ⚙️ Requirements
- Python 3.7+
- Flask
- Google Gemini API key
- Modern web browser

---

## 🤝 Contributing
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

---

## 📄 License
MIT License - see LICENSE file for details

---

## 🔒 Security Notice
This tool helps identify security vulnerabilities but is not a complete security solution. Always follow secure coding practices and conduct thorough security testing.
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
