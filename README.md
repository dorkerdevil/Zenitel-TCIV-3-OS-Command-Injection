# Zenitel TCIV-3+ OS Command Injection Detection Rules

**Author**: Ashish Kunwar (D0rkerDevil)

This repository contains detection rules and scanning tools for the critical OS command injection vulnerabilities in Zenitel TCIV-3+ devices (CVE-2025-64126, CVE-2025-64127, CVE-2025-64128).

## 🚨 Vulnerabilities

### CVE-2025-64126 ⚠️ CRITICAL
- **CVSSv3 Score**: **10.0 (CRITICAL)**
- **CVSSv4 Score**: **10.0**
- **Type**: OS Command Injection (CWE-78)
- **Impact**: Unauthenticated remote code execution
- **Root Cause**: Insufficient input validation on IP address parameter
- **Affected Products**: Zenitel TCIV-3+ (all versions < 9.3.3.0)
- **Fixed Version**: 9.3.3.0 or later
- **Published**: 2025-11-26

### CVE-2025-64127, CVE-2025-64128
- **Type**: OS Command Injection (CWE-78)
- **Impact**: Unauthenticated remote code execution
- **Affected Products**: Zenitel TCIV-3+ (all versions < 9.3.3.0)
- **Fixed Version**: 9.3.3.0 or later

## 📋 Vulnerability Details

**CVE-2025-64126** is a **CRITICAL (CVSS 10.0)** vulnerability that allows unauthenticated remote code execution.

The vulnerability exists because the application accepts a parameter (likely an IP address) directly from user input without properly:
1. Validating if it's a valid IP address format
2. Filtering potentially harmful characters (command separators like `;`, `&&`, `|`, etc.)

This allows an **unauthenticated attacker** to inject arbitrary OS commands, potentially leading to:
- Complete system compromise
- Data exfiltration
- Lateral movement within the network
- Persistence mechanisms
- Device takeover

## 🛠️ Detection Tools

### Nuclei Templates

Two Nuclei templates are provided for automated scanning:

#### `cve-2025-64126.yaml`
- **Purpose**: Version detection for vulnerable Zenitel devices
- **Severity**: Critical
- **Features**:
  - Detects firmware versions from JavaScript parameters
  - Identifies vulnerable versions (< 9.3.3.0)
  - Extracts version numbers for reporting

#### `zenitel-default-credentials.yaml`
- **Purpose**: Tests for default credentials on Zenitel devices
- **Severity**: High
- **Features**:
  - Tests `admin:alphaadmin` and `admin:admin` credentials
  - Uses Basic Authentication
  - Verifies successful authentication

**Installation:**
```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

**Usage:**
```bash
# Single target
nuclei -u http://target.com -t cve-2025-64126.yaml
nuclei -u http://target.com -t zenitel-default-credentials.yaml

# Multiple targets
nuclei -l targets.txt -t cve-2025-64126.yaml -t zenitel-default-credentials.yaml

# With Shodan Uncover (requires SHODAN_API_KEY environment variable)
export SHODAN_API_KEY="your-api-key"
nuclei -uc -uq 'http.html:Zenitel' -ue shodan -ul 100 \
  -t cve-2025-64126.yaml -t zenitel-default-credentials.yaml

# Output to file
nuclei -u http://target.com -t cve-2025-64126.yaml -o results.txt
```

## 📊 Scan Results

During testing, we found:
- **343 vulnerable devices** with versions < 9.3.3.0
- **89 devices** using default credentials (`admin:alphaadmin`)
- Devices exposed across multiple countries and networks

## 🔍 Common Vulnerable Endpoints

Based on analysis, likely vulnerable endpoints include:
- Network configuration endpoints (`/goform/zForm_network`)
- System configuration (`/goform/zForm_system`)
- Ping/test connectivity endpoints
- SNMP configuration
- NTP server configuration
- DNS server configuration
- Gateway configuration


## 📚 References

- [CISA Advisory ICSA-25-329-03](https://www.cisa.gov/news-events/ics-advisories/icsa-25-329-03)
- [NVD CVE-2025-64126](https://nvd.nist.gov/vuln/detail/CVE-2025-64126)
- [Zenitel Downloads](https://wiki.zenitel.com/wiki/Downloads#Station_and_Device_Firmware_Package_.28VS-IS.29)
- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)

## ⚠️ Legal Disclaimer

**WARNING**: Only test on systems you own or have explicit written authorization to test. Unauthorized access to computer systems is illegal. These tools are for educational and authorized security testing purposes only.

## 📝 License

This project is provided as-is for security research and authorized testing purposes.

## 👤 Author

**Ashish Kunwar (D0rkerDevil)**

For questions or issues, please open an issue on the repository.
