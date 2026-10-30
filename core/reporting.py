import csv
import json
import logging
import smtplib
import ssl
from email.message import EmailMessage

from colorama import Fore, Style

try:
    from jinja2 import Template
    HAS_JINJA = True
except ImportError:
    HAS_JINJA = False

logger = logging.getLogger("NemesisScanner")


class Reporter:
    @staticmethod
    def console_report(data: dict, verbose: bool = False):
        print(Fore.CYAN + "=" * 70)
        print(Fore.YELLOW + f"  Scan Report for {data['target']}")
        print(Fore.YELLOW + f"  OS: {data.get('os', 'Unknown')} | Time: {data['timestamp']}")
        print(Fore.CYAN + "=" * 70 + Style.RESET_ALL)

        print(Fore.GREEN + "\n[Services]")
        for service in data["services"]:
            print(f"  {service}")
        if not data["services"]:
            print("  No open services found.")

        print(Fore.GREEN + "\n[Module Classification]")
        if data["modules"]:
            for module, services in data["modules"].items():
                if services:
                    print(Fore.MAGENTA + f"  {module}:")
                    for service in services:
                        print(f"    - {service}")
        else:
            print("  No modules matched.")

        if data.get("vulnerabilities"):
            print(Fore.RED + "\n[Vulnerabilities & Exploits]")
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
            for service, vulnerabilities in data["vulnerabilities"].items():
                sorted_vulnerabilities = sorted(
                    vulnerabilities,
                    key=lambda item: severity_order.get(item.get("severity", "UNKNOWN"), 4),
                )
                print(f"  {service}:")
                for vulnerability in sorted_vulnerabilities:
                    severity = vulnerability.get("severity", "UNKNOWN")
                    color = (
                        Fore.RED if severity == "CRITICAL"
                        else Fore.LIGHTRED_EX if severity == "HIGH"
                        else Fore.YELLOW if severity == "MEDIUM"
                        else Fore.BLUE
                    )
                    print(color + f"    [{severity}] {vulnerability.get('description', '')}")
                    if vulnerability.get("cve"):
                        print(
                            Fore.YELLOW
                            + f"        CVE: {vulnerability['cve']} "
                            + f"(CVSS: {vulnerability.get('cvss_score', 'N/A')})  | "
                            + f"Exploit-DB: {vulnerability.get('exploitdb_url', '')}"
                        )
                    for exploit in vulnerability.get("exploits", []):
                        print(Fore.MAGENTA + f"        Exploit: {exploit['title']} ({exploit['url']})")

    @staticmethod
    def json_report(data: dict, output_path: str):
        with open(output_path, "w") as output_file:
            json.dump(data, output_file, indent=2, default=str)
        logger.info(f"JSON report saved to {output_path}")

    @staticmethod
    def csv_report(data: dict, output_path: str):
        with open(output_path, "w", newline="") as output_file:
            writer = csv.writer(output_file)
            writer.writerow([
                "Proto/Port", "Service", "Product", "Version", "CVE",
                "Severity", "CVSS", "Description", "Exploit Links",
            ])
            for service in data.get("raw_services", []):
                key = (
                    f"{service['proto']}/{service['port']} {service['name']} "
                    f"{service.get('product', '')} {service.get('version', '')}"
                ).strip()
                vulnerabilities = data.get("vulnerabilities", {}).get(key, [])
                if not vulnerabilities:
                    writer.writerow([
                        f"{service['proto']}/{service['port']}",
                        service["name"],
                        service.get("product", ""),
                        service.get("version", ""),
                        "", "", "", "", "",
                    ])
                else:
                    for vulnerability in vulnerabilities:
                        exploit_links = "; ".join(
                            exploit["url"] for exploit in vulnerability.get("exploits", [])
                        )
                        writer.writerow([
                            f"{service['proto']}/{service['port']}",
                            service["name"],
                            service.get("product", ""),
                            service.get("version", ""),
                            vulnerability.get("cve", ""),
                            vulnerability.get("severity", ""),
                            vulnerability.get("cvss_score", ""),
                            vulnerability.get("description", ""),
                            exploit_links,
                        ])
        logger.info(f"CSV report saved to {output_path}")

    @staticmethod
    def html_report(data: dict, output_path: str):
        if not HAS_JINJA:
            logger.warning("Jinja2 not installed, skipping HTML report.")
            return
        template_str = """<!DOCTYPE html>
<html><head><title>Scan Report {{ target }}</title>
<style>body{font-family:Arial;margin:20px;}table{border-collapse:collapse;width:100%;}
th,td{border:1px solid #ddd;padding:8px;}th{background:#4CAF50;color:white;}
.vuln{color:red;}.exploit{color:darkorange;}
.critical{background:#ffcccc;} .high{background:#ffe6e6;} .medium{background:#fff3cd;} .low{background:#e2f0d9;}
</style></head><body>
<h1>Scan Report: {{ target }}</h1>
<p>OS: {{ os }} | Time: {{ timestamp }}</p>
<h2>Open Services</h2>
<table><tr><th>Proto/Port</th><th>Service</th><th>Product</th><th>Version</th><th>Vulnerabilities</th></tr>
{% for s in raw_services %}
{% set key = (s.proto~'/'~s.port~' '~s.name~' '~(s.product or '')~' '~(s.version or '')).strip() %}
{% set vlist = vuln_map.get(key, []) %}
{% if vlist %}
  {% for v in vlist %}
  {% set sev = v.severity|lower %}
  <tr class="{{ sev }}">
    <td>{{ s.proto }}/{{ s.port }}</td>
    <td>{{ s.name }}</td>
    <td>{{ s.product or '' }}</td>
    <td>{{ s.version or '' }}</td>
    <td class="vuln">
      [{{ v.severity }}] {{ v.description }} ({{ v.cve }} CVSS:{{ v.cvss_score }})
      <br><span class="exploit">Exploit-DB: <a href="{{ v.exploitdb_url }}">{{ v.exploitdb_url }}</a></span>
      {% for e in v.exploits %}
        <br><a href="{{ e.url }}">{{ e.title }}</a>
      {% endfor %}
    </td>
  </tr>
  {% endfor %}
{% else %}
  <tr>
    <td>{{ s.proto }}/{{ s.port }}</td>
    <td>{{ s.name }}</td>
    <td>{{ s.product or '' }}</td>
    <td>{{ s.version or '' }}</td>
    <td></td>
  </tr>
{% endif %}
{% endfor %}
</table>
<h2>Attack Surface Modules</h2>
{% for mod, svcs in modules.items() %}{% if svcs %}
<h3>{{ mod }}</h3><ul>{% for s in svcs %}<li>{{ s }}</li>{% endfor %}</ul>
{% endif %}{% endfor %}
</body></html>"""
        rendered = Template(template_str).render(
            target=data["target"],
            os=data.get("os", ""),
            timestamp=data["timestamp"],
            raw_services=data.get("raw_services", []),
            modules=data.get("modules", {}),
            vuln_map=data.get("vulnerabilities", {}),
        )
        with open(output_path, "w") as output_file:
            output_file.write(rendered)
        logger.info(f"HTML report saved to {output_path}")

    @staticmethod
    def send_email(data: dict, smtp_config: dict):
        try:
            message = EmailMessage()
            message["Subject"] = (
                f"⚡ Scan Report for {data['target']} – "
                f"{sum(len(items) for items in data.get('vulnerabilities', {}).values())} vulns found"
            )
            message["From"] = smtp_config["from"]
            message["To"] = smtp_config["to"]
            body = f"OS: {data.get('os')}\n\nServices:\n"
            body += "\n".join(data["services"])
            if data.get("vulnerabilities"):
                body += "\n\nCRITICAL VULNERABILITIES:\n"
                for service, vulnerabilities in data["vulnerabilities"].items():
                    body += f"\n{service}:\n"
                    for vulnerability in vulnerabilities:
                        body += (
                            f"  - [{vulnerability.get('severity', '')}] "
                            f"{vulnerability['description']} ({vulnerability.get('cve', '')})\n"
                        )
            message.set_content(body)
            context = ssl.create_default_context()
            with smtplib.SMTP(smtp_config["server"], smtp_config["port"]) as smtp:
                smtp.ehlo()
                smtp.starttls(context=context)
                smtp.login(smtp_config["user"], smtp_config["password"])
                smtp.send_message(message)
            logger.info("Email sent successfully.")
        except Exception as error:
            logger.error(f"Email failed: {error}")

    @staticmethod
    def slack_webhook(data: dict, webhook_url: str):
        import requests

        blocks = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*⚡ Scan Report for {data['target']}*\nOS: {data.get('os')}",
                },
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "Services:\n" + "\n".join(f"• {service}" for service in data["services"]),
                },
            },
        ]
        if data.get("vulnerabilities"):
            vulnerability_text = "⚠️ *Vulnerabilities:*\n"
            for service, vulnerabilities in list(data["vulnerabilities"].items())[:5]:
                vulnerability_text += f"\n*{service}*:\n"
                for vulnerability in vulnerabilities[:2]:
                    vulnerability_text += (
                        f"  - [{vulnerability.get('severity', '')}] "
                        f"{vulnerability['description']} ({vulnerability.get('cve', '')})\n"
                    )
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": vulnerability_text},
            })
        payload = {"text": f"Scan complete: {data['target']}", "blocks": blocks}
        try:
            response = requests.post(webhook_url, json=payload, timeout=10)
            if response.status_code == 200:
                logger.info("Slack notification sent.")
            else:
                logger.warning(f"Slack webhook failed: {response.status_code}")
        except Exception as error:
            logger.error(f"Slack error: {error}")