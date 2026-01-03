from __future__ import annotations

from webforti_common.models import CVERecord


SEED_CVES = {
    "CVE-2021-41773": CVERecord(
        cve_id="CVE-2021-41773",
        title="Apache HTTP Server path traversal and file disclosure",
        description=(
            "A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. "
            "An attacker could use a path traversal attack to map URLs to files outside expected directories."
        ),
        severity="HIGH",
        cvss_score=7.5,
        published_at="2021-10-05T00:00:00Z",
    ),
    "CVE-2022-22965": CVERecord(
        cve_id="CVE-2022-22965",
        title="Spring Framework remote code execution through data binding",
        description=(
            "Spring Framework applications running on JDK 9+ may be vulnerable to remote code execution "
            "through crafted class loader parameters in HTTP requests."
        ),
        severity="CRITICAL",
        cvss_score=9.8,
        published_at="2022-04-01T00:00:00Z",
    ),
    "CVE-2021-42013": CVERecord(
        cve_id="CVE-2021-42013",
        title="Apache HTTP Server path traversal and command execution",
        description=(
            "Apache HTTP Server 2.4.50 incompletely fixed the path normalization flaw from CVE-2021-41773. "
            "Attackers could use encoded traversal sequences in HTTP paths against vulnerable configurations."
        ),
        severity="CRITICAL",
        cvss_score=9.8,
        published_at="2021-10-07T00:00:00Z",
    ),
    "CVE-2022-1388": CVERecord(
        cve_id="CVE-2022-1388",
        title="F5 BIG-IP iControl REST authentication bypass",
        description=(
            "F5 BIG-IP iControl REST requests to management endpoints such as /mgmt/tm/util/bash could bypass "
            "authentication and reach command execution functionality on vulnerable systems."
        ),
        severity="CRITICAL",
        cvss_score=9.8,
        published_at="2022-05-04T00:00:00Z",
    ),
    "CVE-2023-29489": CVERecord(
        cve_id="CVE-2023-29489",
        title="cPanel XSS through crafted URL parameter",
        description=(
            "A reflected cross-site scripting vulnerability can be triggered with a crafted web request "
            "containing script payload indicators."
        ),
        severity="MEDIUM",
        cvss_score=6.1,
        published_at="2023-04-26T00:00:00Z",
    ),
    "CVE-2019-19781": CVERecord(
        cve_id="CVE-2019-19781",
        title="Citrix ADC and Gateway path traversal",
        description=(
            "Citrix ADC and Gateway appliances exposed path traversal behavior in VPN web paths. "
            "Exploit probes often target paths under /vpn/../vpns/ to reach configuration or template files."
        ),
        severity="CRITICAL",
        cvss_score=9.8,
        published_at="2019-12-17T00:00:00Z",
    ),
    "CVE-2021-44228": CVERecord(
        cve_id="CVE-2021-44228",
        title="Apache Log4j JNDI lookup remote code execution",
        description=(
            "Apache Log4j 2 lookup strings such as ${jndi:ldap://host/a} in attacker-controlled HTTP values "
            "could trigger remote lookup behavior in vulnerable Java applications."
        ),
        severity="CRITICAL",
        cvss_score=10.0,
        published_at="2021-12-10T00:00:00Z",
    ),
    "CVE-2020-5902": CVERecord(
        cve_id="CVE-2020-5902",
        title="F5 BIG-IP TMUI path traversal remote code execution",
        description=(
            "F5 BIG-IP TMUI exposed path traversal through crafted HTTP paths such as "
            "/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp on vulnerable management interfaces."
        ),
        severity="CRITICAL",
        cvss_score=9.8,
        published_at="2020-07-01T00:00:00Z",
    ),
}


SEED_KNOWLEDGE = [
    {
        "id": "snort-http-content-template",
        "title": "Snort HTTP content rule template",
        "text": "Use alert tcp any any -> $HOME_NET $HTTP_PORTS with flow:to_server,established and content match on URI or body payload indicators.",
        "source": "seed",
    },
    {
        "id": "apache-path-traversal-pattern",
        "title": "Apache path traversal payload pattern",
        "text": "Apache HTTP Server 2.4.49 path traversal probes often contain /.%2e/ encoded traversal in the URI.",
        "source": "seed",
        "cve_id": "CVE-2021-41773",
    },
    {
        "id": "spring4shell-parameter-pattern",
        "title": "Spring4Shell HTTP parameter pattern",
        "text": "Spring class loader exploitation attempts commonly include class.module.classLoader in request parameters.",
        "source": "seed",
        "cve_id": "CVE-2022-22965",
    },
    {
        "id": "apache-42013-traversal-pattern",
        "title": "Apache 2.4.50 traversal pattern",
        "text": "Apache HTTP Server 2.4.50 CVE-2021-42013 probes reuse encoded traversal strings such as /.%2e/ in CGI paths.",
        "source": "seed",
        "cve_id": "CVE-2021-42013",
    },
    {
        "id": "f5-icontrol-rest-bash-pattern",
        "title": "F5 iControl REST util bash pattern",
        "text": "F5 BIG-IP CVE-2022-1388 exploit attempts commonly target the /mgmt/tm/util/bash iControl REST endpoint.",
        "source": "seed",
        "cve_id": "CVE-2022-1388",
    },
    {
        "id": "citrix-adc-vpn-traversal-pattern",
        "title": "Citrix ADC VPN traversal pattern",
        "text": "Citrix ADC CVE-2019-19781 probes commonly include /vpn/../vpns/ path traversal indicators.",
        "source": "seed",
        "cve_id": "CVE-2019-19781",
    },
    {
        "id": "log4shell-jndi-lookup-pattern",
        "title": "Log4Shell JNDI lookup pattern",
        "text": "Log4Shell probes include ${jndi:ldap://...} lookup strings in HTTP headers, parameters, or body values.",
        "source": "seed",
        "cve_id": "CVE-2021-44228",
    },
    {
        "id": "f5-tmui-file-read-pattern",
        "title": "F5 TMUI traversal pattern",
        "text": "F5 BIG-IP TMUI CVE-2020-5902 probes include /tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp.",
        "source": "seed",
        "cve_id": "CVE-2020-5902",
    },
    {
        "id": "sandbox-safety-policy",
        "title": "WebForti sandbox safety policy",
        "text": "Verification must use attacker, target, and Snort sensor containers on an isolated bridge network with no external egress.",
        "source": "seed",
    },
]
