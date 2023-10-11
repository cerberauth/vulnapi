# VulnAPI: An API Security Vulnerability Scanner

## Overview

As APIs are becoming increasingly essential, they are also becoming prime targets for security breaches. To protect your APIs, it's vital to proactively identify and address security vulnerabilities.

VulnAPI is an open-source project designed to help you scan your APIs for common security vulnerabilities and weaknesses. By using this tool, you can detect that some API potential vulnerabilities and fix security issues.

## Get Started

To use this tool, follow the bellow instructions:
1. Download the binary from the latest [release](https://github.com/cerberauth/vulnapi/releases).
2. Run the following command: `vulnapi scan http://localhost:8080/`

Depending on the scan you run, you may have to pass existing valid JWT.

You can test the scanner against example [vulnerability challenges](https://github.com/cerberauth/api-vulns-challenges).

## Documentation

### Command line documentation

Run `vulnapi -h` or `vulnapi help`.

## Disclaimer

This scanner is provided for educational and informational purposes only. It should not be used for malicious purposes or to attack any system without proper authorization. Always respect the security and privacy of others.

## License

This repository is licensed under the MIT license License. You are free to use, modify, and distribute the contents of this repository for educational and testing purposes.
