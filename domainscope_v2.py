import socket
import ssl
import requests
import whois
import dns.resolver

BANNER = """
=========================================
      DOMAINSCOPE V2
 Domain Intelligence Scanner
=========================================
"""


def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return "Unable to Resolve"


def get_whois(domain):
    try:
        return whois.whois(domain)
    except:
        return None


def get_dns_records(domain):
    records = {}

    record_types = ["A", "MX", "NS", "TXT"]

    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records[record_type] = [str(r) for r in answers]
        except:
            records[record_type] = []

    return records


def get_ssl_info(domain):
    try:
        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(
                sock,
                server_hostname=domain
            ) as ssock:

                cert = ssock.getpeercert()

                issuer = dict(
                    x[0]
                    for x in cert["issuer"]
                )

                expiry = cert["notAfter"]

                return {
                    "issuer": issuer.get(
                        "organizationName",
                        "Unknown"
                    ),
                    "expiry": expiry
                }

    except:
        return None


def get_headers(domain):

    try:

        response = requests.get(
            f"https://{domain}",
            timeout=5,
            allow_redirects=True
        )

        headers = response.headers

        checks = {
            "HSTS":
                "Strict-Transport-Security" in headers,

            "CSP":
                "Content-Security-Policy" in headers,

            "X-Frame-Options":
                "X-Frame-Options" in headers,

            "X-Content-Type-Options":
                "X-Content-Type-Options" in headers
        }

        return checks

    except:
        return None


def calculate_grade(headers):

    if not headers:
        return "F"

    score = sum(headers.values())

    if score == 4:
        return "A"

    if score == 3:
        return "B"

    if score == 2:
        return "C"

    if score == 1:
        return "D"

    return "F"


def print_dns(records):

    print("\n========== DNS ==========")

    for rtype, values in records.items():

        print(f"\n{rtype} Records:")

        if values:

            for v in values:
                print("   ", v)

        else:
            print("   None Found")


def main():

    print(BANNER)

    domain = input(
        "Enter Domain: "
    ).strip()

    print("\nGenerating Report...\n")

    print("=" * 50)

    print(f"Domain: {domain}")

    ip = get_ip(domain)

    print(f"IP Address: {ip}")

    print("\n========== WHOIS ==========")

    w = get_whois(domain)

    if w:

        print(
            f"Registrar: {w.registrar}"
        )

        created = w.creation_date

        if isinstance(created, list):
            created = created[0]

        print(
            f"Created: {created}"
        )

    dns_records = get_dns_records(domain)

    print_dns(dns_records)

    ssl_info = get_ssl_info(domain)

    print("\n========== SSL ==========")

    if ssl_info:

        print(
            f"Issuer: {ssl_info['issuer']}"
        )

        print(
            f"Expiry: {ssl_info['expiry']}"
        )

    headers = get_headers(domain)

    print(
        "\n========== SECURITY HEADERS =========="
    )

    if headers:

        for k, v in headers.items():

            status = (
                "YES"
                if v
                else "NO"
            )

            print(
                f"[{status}] {k}"
            )

    grade = calculate_grade(headers)

    print(
        f"\nSecurity Grade: {grade}"
    )

    print("=" * 50)

    report = f"""
=========================================
DOMAINSCOPE REPORT
=========================================

Domain: {domain}
IP Address: {ip}
Security Grade: {grade}

=========================================
"""

    safe_domain = (
        domain.replace(".", "_")
    )

    filename = (
        f"{safe_domain}_report.txt"
    )

    with open(
        filename,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(report)

    print(
        f"\nReport saved as {filename}"
    )


if __name__ == "__main__":
    main()