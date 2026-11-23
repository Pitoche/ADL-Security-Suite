"""Explicit mapping of approved scanners to original scripts."""

from pathlib import Path

SCANNER_BASE = Path("/home/angel/ADL-TOOL-Repository/vul-tool")

SCANNER_PATHS = {
    "static": {
        "Bandit": "static-tools/bandit_scan.py",
        "Grype": "static-tools/grype_scan.py",
        "Lynis": "static-tools/lynis_os_scan.py",
        "SonarScanner": "static-tools/sonar_scan.py",
        "Semgrep": "static-tools/semgrep_scan.py",
    },
    "dynamic": {
        "ZAP": "dynamic-tools/zap_scan.py",
        "Nmap": "dynamic-tools/nmap_scan.py",
    },
    "dependency": {
        "snyk": "dependency-tools/snyk_scan.py",
        "PythonDeps": "dependency-tools/python-dependencies-audit.py",
        "Trivy": "dependency-tools/trivy_scan.py",
        "dependency-check": "dependency-tools/dependency_check_scan.py",
    },
    "docker": {
        "DockerBandit": "docker-tools/docker_bandit_runner.py",
        "DockerTrivy": "docker-tools/docker_trivy_runner.py",
    },
    "iot": {
        "binwalk": "iot-tools/binwalk_scan.py",
        "firmwalker": "iot-tools/firmwalker_scan.py",
        "jefferson": "iot-tools/jefferson_scan.py",
        "retdec": "iot-tools/retdec_scan.py",
    },
}


def scanner_inventory():
    """Return scanner paths and file availability without executing them."""
    inventory = {}

    for category, tools in SCANNER_PATHS.items():
        inventory[category] = {}

        for name, relative_path in tools.items():
            path = SCANNER_BASE / relative_path

            inventory[category][name] = {
                "path": str(path),
                "script_exists": path.is_file(),
                "execution_enabled": False,
            }

    return inventory
