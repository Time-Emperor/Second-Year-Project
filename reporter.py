import json
from jinja2 import Template

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AHHCS Host Hardening Audit Report</title>
    <style>
        :root {
            --bg-color: #ffffff;
            --card-bg: #f8fafc;
            --text-primary: #111827;
            --text-secondary: #4b5563;
            --pass-color: #16a34a;
            --fail-color: #dc2626;
            
            --high-color: #dc2626;
            --medium-color: #ca8a04;
            --low-color: #16a34a;
            --none-color: #64748b;
            
            --border-color: #e2e8f0;
        }
        body {
            font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-primary);
            margin: 0;
            padding: 3rem 2rem;
        }
        .container { max-width: 1100px; margin: 0 auto; }
        .header { 
            display: flex; 
            justify-content: space-between; 
            align-items: center; 
            background: var(--card-bg);
            padding: 2rem;
            border-radius: 12px;
            border: 1px solid var(--border-color);
            margin-bottom: 2rem;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
        }
        .header h1 { margin: 0 0 0.25rem 0; font-size: 1.8rem; color: var(--text-primary); }
        .header p { color: var(--text-secondary); margin: 0; }
        
        .header-actions { display: flex; align-items: center; gap: 1.5rem; }
        .btn-pdf {
            background-color: #2563eb;
            color: white;
            border: none;
            padding: 0.75rem 1.25rem;
            border-radius: 8px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s;
        }
        .btn-pdf:hover { background-color: #1d4ed8; }

        .score-box { text-align: center; }
        .score { font-size: 2.5rem; font-weight: 800; color: var(--pass-color); line-height: 1; }
        .score-label { font-size: 0.75rem; color: var(--text-secondary); text-transform: uppercase; margin-top: 0.3rem; letter-spacing: 0.05em; font-weight: 600; }
        
        .severity-section { margin-bottom: 2rem; }
        .section-title { 
            font-size: 1.1rem; 
            font-weight: 700; 
            text-transform: uppercase; 
            letter-spacing: 0.05em; 
            margin-bottom: 1rem; 
        }
        .title-high { color: var(--high-color); }
        .title-medium { color: var(--medium-color); }
        .title-low { color: var(--low-color); }
        .title-none { color: var(--none-color); }

        .card { 
            background: var(--card-bg); 
            border-radius: 10px; 
            padding: 1.25rem 1.5rem; 
            margin-bottom: 1rem; 
            border: 1px solid var(--border-color);
            box-shadow: 0 1px 2px rgba(0, 0, 0, 0.02);
        }
        .card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; }
        .rule-title { font-size: 1.05rem; font-weight: 600; color: var(--text-primary); }
        
        .badge { padding: 0.3rem 0.6rem; border-radius: 6px; font-size: 0.75rem; font-weight: 700; letter-spacing: 0.05em; }
        .badge-pass { background-color: #dcfce7; color: #15803d; border: 1px solid #bbf7d0; }
        .badge-fail { background-color: #fee2e2; color: #b91c1c; border: 1px solid #fecaca; }
        
        .meta-grid { display: flex; gap: 2rem; font-size: 0.9rem; color: var(--text-secondary); }
        .meta-grid span strong { color: var(--text-primary); }
        
        code { background: #f1f5f9; padding: 0.2rem 0.4rem; border-radius: 4px; color: #0284c7; font-family: monospace; border: 1px solid #e2e8f0; }
        .error-msg { color: var(--fail-color); margin-top: 0.75rem; font-size: 0.9rem; font-weight: 500; }

        @media print {
            body { background-color: white; color: black; padding: 0; }
            .btn-pdf { display: none; }
            .card, .header { border: 1px solid #cbd5e1; box-shadow: none; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>AHHCS Host Hardening Audit</h1>
                <p>Automated Compliance and Security Benchmark Report</p>
            </div>
            <div class="header-actions">
                <button class="btn-pdf" onclick="window.print()">
                    Export PDF Report
                </button>
                <div class="score-box">
                    <div class="score">{{ score.score_percentage }}%</div>
                    <div class="score-label">Compliance Score</div>
                </div>
            </div>
        </div>

        <!-- High Severity Group -->
        {% set high_items = results | selectattr('severity', 'equalto', 'High') | list %}
        {% if high_items %}
        <div class="severity-section">
            <div class="section-title title-high">High Severity Findings ({{ high_items | length }})</div>
            {% for item in high_items %}
            <div class="card">
                <div class="card-header">
                    <div class="rule-title">[{{ item.rule_id }}] {{ item.description }}</div>
                    <span class="badge {{ 'badge-pass' if item.passed else 'badge-fail' }}">
                        {{ 'PASS' if item.passed else 'FAIL' }}
                    </span>
                </div>
                <div class="meta-grid">
                    <span>Category: <strong>{{ item.category | upper }}</strong></span>
                    <span>Expected: <code>{{ item.expected }}</code></span>
                    <span>Actual: <code>{{ item.actual }}</code></span>
                </div>
                {% if not item.passed and item.error %}
                <div class="error-msg">Notice: {{ item.error }}</div>
                {% endif %}
            </div>
            {% endfor %}
        </div>
        {% endif %}

        <!-- Medium Severity Group -->
        {% set med_items = results | selectattr('severity', 'equalto', 'Medium') | list %}
        {% if med_items %}
        <div class="severity-section">
            <div class="section-title title-medium">Medium Severity Findings ({{ med_items | length }})</div>
            {% for item in med_items %}
            <div class="card">
                <div class="card-header">
                    <div class="rule-title">[{{ item.rule_id }}] {{ item.description }}</div>
                    <span class="badge {{ 'badge-pass' if item.passed else 'badge-fail' }}">
                        {{ 'PASS' if item.passed else 'FAIL' }}
                    </span>
                </div>
                <div class="meta-grid">
                    <span>Category: <strong>{{ item.category | upper }}</strong></span>
                    <span>Expected: <code>{{ item.expected }}</code></span>
                    <span>Actual: <code>{{ item.actual }}</code></span>
                </div>
                {% if not item.passed and item.error %}
                <div class="error-msg">Notice: {{ item.error }}</div>
                {% endif %}
            </div>
            {% endfor %}
        </div>
        {% endif %}

        <!-- Low Severity Group -->
        {% set low_items = results | selectattr('severity', 'equalto', 'Low') | list %}
        {% if low_items %}
        <div class="severity-section">
            <div class="section-title title-low">Low Severity Findings ({{ low_items | length }})</div>
            {% for item in low_items %}
            <div class="card">
                <div class="card-header">
                    <div class="rule-title">[{{ item.rule_id }}] {{ item.description }}</div>
                    <span class="badge {{ 'badge-pass' if item.passed else 'badge-fail' }}">
                        {{ 'PASS' if item.passed else 'FAIL' }}
                    </span>
                </div>
                <div class="meta-grid">
                    <span>Category: <strong>{{ item.category | upper }}</strong></span>
                    <span>Expected: <code>{{ item.expected }}</code></span>
                    <span>Actual: <code>{{ item.actual }}</code></span>
                </div>
                {% if not item.passed and item.error %}
                <div class="error-msg">Notice: {{ item.error }}</div>
                {% endif %}
            </div>
            {% endfor %}
        </div>
        {% endif %}

        <!-- None Severity Group -->
        {% set none_items = results | selectattr('severity', 'equalto', 'None') | list %}
        {% if none_items %}
        <div class="severity-section">
            <div class="section-title title-none">General / Unclassified Findings ({{ none_items | length }})</div>
            {% for item in none_items %}
            <div class="card">
                <div class="card-header">
                    <div class="rule-title">[{{ item.rule_id }}] {{ item.description }}</div>
                    <span class="badge {{ 'badge-pass' if item.passed else 'badge-fail' }}">
                        {{ 'PASS' if item.passed else 'FAIL' }}
                    </span>
                </div>
                <div class="meta-grid">
                    <span>Category: <strong>{{ item.category | upper }}</strong></span>
                    <span>Expected: <code>{{ item.expected }}</code></span>
                    <span>Actual: <code>{{ item.actual }}</code></span>
                </div>
                {% if not item.passed and item.error %}
                <div class="error-msg">Notice: {{ item.error }}</div>
                {% endif %}
            </div>
            {% endfor %}
        </div>
        {% endif %}

    </div>
</body>
</html>
"""

def export_html_report(audit_results: list, score_data: dict, output_filepath: str):
    template = Template(HTML_TEMPLATE)
    rendered_html = template.render(results=audit_results, score=score_data)
    with open(output_filepath, 'w', encoding='utf-8') as f:
        f.write(rendered_html)
    print(f"[+] Compliance HTML dashboard exported successfully to: {output_filepath}")

def export_json_output(audit_results: list, score_data: dict):
    payload = {"score": score_data, "audit_results": audit_results}
    print(json.dumps(payload, indent=2))