import re
import requests
from flask import Flask, request, render_template_string, redirect, url_for
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

app = Flask(__name__)

# Basic payloads for testing vulnerabilities
XSS_TEST_PAYLOAD = "<script>alert(1)</script>"
SQLI_TEST_PAYLOADS = ["' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--", "\" OR 1=1--"]

CSRF_TOKEN_NAMES = [
    "csrf_token",
    "csrfmiddlewaretoken",
    "xsrf-token",
    "authenticity_token",
    "__RequestVerificationToken",
]

MATERIAL_ICONS_CSS = "https://fonts.googleapis.com/icon?family=Material+Icons"

# Template for the main page and results
PAGE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Web Application Vulnerability Scanner</title>
    <link href="{{ material_icons }}" rel="stylesheet" />
    <style>
        /* Modern CSS styling, responsive and clean */
        :root {
            --primary-color: #6200ea;
            --secondary-color: #03dac6;
            --background-color: #f5f5f5;
            --text-color: #121212;
            --card-background: #ffffff;
            --danger-color: #b00020;
            --warning-color: #ff6f00;
            --success-color: #2e7d32;
            --font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen,
                Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
        }
        * {
            box-sizing: border-box;
        }
        body {
            font-family: var(--font-family);
            background-color: var(--background-color);
            color: var(--text-color);
            margin: 0;
            padding: 0;
            line-height: 1.5;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }
        header {
            background: var(--primary-color);
            color: white;
            padding: 16px 24px;
            text-align: center;
            font-size: 1.5rem;
            font-weight: 700;
            box-shadow: 0 2px 4px rgba(0,0,0,0.2);
            flex-shrink: 0;
        }
        main {
            flex-grow: 1;
            padding: 24px;
            max-width: 900px;
            margin: auto;
            width: 100%;
            box-sizing: border-box;
        }
        form {
            display: flex;
            flex-wrap: nowrap;
            gap: 12px;
            margin-bottom: 32px;
            justify-content: center;
        }
        input[type="url"] {
            flex-grow: 1;
            padding: 12px 16px;
            font-size: 1rem;
            border: 2px solid var(--primary-color);
            border-radius: 8px;
            transition: border-color 0.3s ease;
            min-width: 0;
        }
        input[type="url"]:focus {
            outline: none;
            border-color: var(--secondary-color);
            box-shadow: 0 0 6px var(--secondary-color);
        }
        button {
            background: var(--primary-color);
            border: none;
            color: white;
            font-weight: 600;
            padding: 0 24px;
            border-radius: 8px;
            cursor: pointer;
            transition: background 0.3s ease;
            font-size: 1rem;
        }
        button:hover {
            background: var(--secondary-color);
            color: var(--text-color);
        }
        .results {
            background: var(--card-background);
            padding: 24px;
            border-radius: 12px;
            box-shadow: 0 6px 12px rgba(0,0,0,0.1);
        }
        h2 {
            margin-top: 0;
            margin-bottom: 16px;
            border-bottom: 2px solid var(--primary-color);
            padding-bottom: 8px;
        }
        ul.vuln-list {
            list-style: none;
            padding: 0;
        }
        ul.vuln-list li {
            margin-bottom: 12px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 8px 12px;
            border-radius: 8px;
        }
        .vuln-xss {
            color: var(--danger-color);
            background: #f8d7da;
        }
        .vuln-sqli {
            color: var(--danger-color);
            background: #f8d7da;
        }
        .vuln-csrf {
            color: var(--warning-color);
            background: #fff3cd;
        }
        .vuln-none {
            color: var(--success-color);
            background: #d4edda;
            font-weight: 700;
            padding: 16px;
            border-radius: 12px;
            text-align: center;
        }
        .icon {
            font-family: 'Material Icons';
            font-weight: normal;
            font-style: normal;
            font-size: 20px;
            line-height: 1;
            user-select: none;
            -webkit-font-smoothing: antialiased;
        }
        footer {
            text-align: center;
            padding: 12px 24px;
            font-size: 0.8rem;
            color: #666;
            background: #eee;
            flex-shrink: 0;
        }
        @media (max-width: 480px) {
            main {
                padding: 16px 12px;
            }
            form {
                flex-direction: column;
                gap: 16px;
            }
            button {
                width: 100%;
                padding: 12px;
            }
        }
    </style>
</head>
<body>
    <header>
        Web Application Vulnerability Scanner
    </header>
    <main>
        <form method="POST" action="/">
            <input type="url" name="target_url" placeholder="Enter target website URL (e.g. https://example.com)" required autofocus />
            <button type="submit" aria-label="Start scan">
                <span class="icon">search</span> Scan
            </button>
        </form>

        {% if error_message %}
            <div class="results vuln-none" role="alert">{{ error_message }}</div>
        {% endif %}

        {% if scan_results %}
            <section class="results" aria-live="polite">
                <h2>Scan Report for <a href="{{ target_url }}" target="_blank" rel="noopener">{{ target_url }}</a></h2>
                {% if scan_results.xss %}
                    <h3>XSS (Cross-Site Scripting) Vulnerabilities</h3>
                    <ul class="vuln-list">
                        {% for finding in scan_results.xss %}
                        <li class="vuln-xss">
                            <span class="icon" aria-hidden="true">warning</span>
                            Parameter: <strong>{{ finding.parameter }}</strong> — Reflected script detected.
                        </li>
                        {% endfor %}
                    </ul>
                {% else %}
                    <h3>XSS (Cross-Site Scripting)</h3>
                    <p class="vuln-none">No XSS vulnerabilities detected.</p>
                {% endif %}

                {% if scan_results.sqli %}
                    <h3>SQL Injection (SQLi) Vulnerabilities</h3>
                    <ul class="vuln-list">
                        {% for finding in scan_results.sqli %}
                        <li class="vuln-sqli">
                            <span class="icon" aria-hidden="true">error</span>
                            Parameter: <strong>{{ finding.parameter }}</strong> — Possible SQL error or injection point.
                        </li>
                        {% endfor %}
                    </ul>
                {% else %}
                    <h3>SQL Injection (SQLi)</h3>
                    <p class="vuln-none">No SQLi vulnerabilities detected.</p>
                {% endif %}

                {% if scan_results.csrf %}
                    <h3>CSRF (Cross-Site Request Forgery) Vulnerabilities</h3>
                    <ul class="vuln-list">
                        {% for finding in scan_results.csrf %}
                        <li class="vuln-csrf">
                            <span class="icon" aria-hidden="true">report_problem</span>
                            Form action: <strong>{{ finding.form_action }}</strong> — Missing CSRF token.
                        </li>
                        {% endfor %}
                    </ul>
                {% else %}
                    <h3>CSRF (Cross-Site Request Forgery)</h3>
                    <p class="vuln-none">No CSRF vulnerabilities detected.</p>
                {% endif %}
            </section>
        {% endif %}
    </main>
    <footer>
        Powered by Python, Flask, Requests, BeautifulSoup | OWASP Top 10 Inspired
    </footer>
</body>
</html>
"""

def fetch_page(url):
    try:
        headers = {'User-Agent': 'VulnScannerBot/1.0 (+https://example.com)'}
        response = requests.get(url, headers=headers, timeout=10, verify=True)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        return None

def check_xss(url):
    """
    Basic reflected XSS check by injecting payload into each query parameter
    """
    findings = []
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    if not query_params:
        # no params to test
        return findings

    for param in query_params:
        # Inject payload into one parameter at a time
        new_params = query_params.copy()
        new_params[param] = [XSS_TEST_PAYLOAD]
        new_query = urlencode(new_params, doseq=True)
        new_url = urlunparse(parsed_url._replace(query=new_query))
        html = fetch_page(new_url)
        if html and XSS_TEST_PAYLOAD in html:
            findings.append({'parameter': param})

    return findings

def check_sqli(url):
    """
    Basic SQLi check by injecting SQLi payloads into each query parameter
    and analyzing response for common SQL error patterns
    """
    findings = []
    sql_errors = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark after the character string",
        "quoted string not properly terminated",
        "pg_query()",
        "sqlstate",
        "mysql_fetch_array()",
        "syntax error",
        "sql error",
        "database error",
        "invalid query",
    ]
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    if not query_params:
        return findings

    for param in query_params:
        for payload in SQLI_TEST_PAYLOADS:
            new_params = query_params.copy()
            new_params[param] = [payload]
            new_query = urlencode(new_params, doseq=True)
            new_url = urlunparse(parsed_url._replace(query=new_query))
            html = fetch_page(new_url)
            if html:
                lower_html = html.lower()
                if any(err in lower_html for err in sql_errors):
                    findings.append({'parameter': param})
                    break

    return findings

def check_csrf(url):
    """
    Check for forms missing CSRF tokens
    """
    findings = []
    html = fetch_page(url)
    if not html:
        return findings

    soup = BeautifulSoup(html, 'html.parser')
    forms = soup.find_all('form')
    for form in forms:
        # Check for hidden input fields matching CSRF token names
        inputs = form.find_all('input', {'type': 'hidden'})
        tokens = [inp.get('name', '').lower() for inp in inputs]
        if not any(token_name.lower() in tokens for token_name in CSRF_TOKEN_NAMES):
            action = form.get('action') or url
            findings.append({'form_action': action})

    return findings

@app.route('/', methods=['GET', 'POST'])
def home():
    error_message = None
    scan_results = None
    target_url = None

    if request.method == 'POST':
        target_url = request.form.get('target_url', '').strip()
        if not target_url:
            error_message = "Please enter a valid URL."
        else:
            # Validate URL scheme
            if not (target_url.startswith('http://') or target_url.startswith('https://')):
                target_url = 'http://' + target_url  # add default scheme

            try:
                # Run scans
                xss_findings = check_xss(target_url)
                sqli_findings = check_sqli(target_url)
                csrf_findings = check_csrf(target_url)

                scan_results = {
                    'xss': xss_findings,
                    'sqli': sqli_findings,
                    'csrf': csrf_findings
                }
            except Exception as e:
                error_message = f"Error during scanning: {str(e)}"

    return render_template_string(PAGE_TEMPLATE,
                                  scan_results=scan_results,
                                  target_url=target_url,
                                  error_message=error_message,
                                  material_icons=MATERIAL_ICONS_CSS)

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)

