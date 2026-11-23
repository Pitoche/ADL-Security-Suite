"""Approved scanning tools available to the IoT module."""

SCANNER_CATALOG = {
    "static": [
        "Bandit",
        "Grype",
        "Lynis",
        "SonarScanner",
        "Semgrep",
    ],
    "dynamic": [
        "ZAP",
        "Nmap",
    ],
    "dependency": [
        "snyk",
        "PythonDeps",
        "Trivy",
        "dependency-check",
    ],
    "docker": [
        "DockerBandit",
        "DockerTrivy",
    ],
    "iot": [
        "binwalk",
        "firmwalker",
        "jefferson",
        "retdec",
    ],
}
