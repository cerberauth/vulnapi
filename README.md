<p align="center">
    <img src="https://vulnapi.cerberauth.com/logo-ascii-text-art.png" height="150" alt="vulnapi logo">
</p>

---

[![Join Discord](https://img.shields.io/discord/1242773130137833493?label=Discord&style=for-the-badge)](https://vulnapi.cerberauth.com/discord)
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/cerberauth/vulnapi/ci.yml?branch=main&label=core%20build&style=for-the-badge)](https://github.com/cerberauth/vulnapi/actions/workflows/ci.yml)
![Latest version](https://img.shields.io/github/v/release/cerberauth/vulnapi?sort=semver&style=for-the-badge)
[![Github Repo Stars](https://img.shields.io/github/stars/cerberauth/vulnapi?style=for-the-badge)](https://github.com/cerberauth/vulnapi)
![License](https://img.shields.io/github/license/cerberauth/vulnapi?style=for-the-badge)

# VulnAPI: An API Security Vulnerability Scanner

VulnAPI is an Open-Source DAST designed to help you scan your APIs for common security vulnerabilities and weaknesses.

By using this tool, you can detect and mitigate security vulnerabilities in your APIs before they are exploited by attackers.

![Demo](demo.gif)

## Documentation

Before scanning, you can discover target API useful information by using the `discover` command.

The Vulnerability Scanner CLI offers two methods for scanning APIs:
* **Using Curl-like CLI**: This method involves directly invoking the CLI with parameters resembling curl commands.
* **Using OpenAPI Contracts**: This method utilizes OpenAPI contracts to specify API endpoints for scanning.

### Discover Command

To discover target API useful information, execute the following command:

```bash
vulnapi discover api [API_URL]
```

Example output:

```bash
| WELL-KNOWN PATHS |                URL                 |
|------------------|------------------------------------|
| OpenAPI          | http://localhost:5000/openapi.json |
| GraphQL          | N/A                                |


| TECHNOLOGIE/SERVICE |     VALUE     |
|---------------------|---------------|
| Framework           | Flask:2.2.3   |
| Language            | Python:3.7.17 |
| Server              | Flask:2.2.3   |
```

### Using Curl-like CLI

To perform a scan using the Curl-like CLI, execute the following command:

```bash
vulnapi scan curl [API_URL] [CURL_OPTIONS]
```

Replace `[API_URL]` with the URL of the API to scan, and `[CURL_OPTIONS]` with any additional curl options you wish to include.

Example:

```bash
vulnapi scan curl http://localhost:8080 -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ."
```

### Using OpenAPI Contracts

To perform a scan using OpenAPI contracts, execute the following command:

```bash
echo "[JWT_TOKEN]" | vulnapi scan openapi [PATH_OR_URL_TO_OPENAPI_FILE]
```

Replace [PATH_OR_URL_TO_OPENAPI_FILE] with the path or the URL to the OpenAPI contract JSON file and [JWT_TOKEN] with the JWT token to use for authentication.

Example:

```bash
echo "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.e30." | vulnapi scan openapi ./test/stub/simple_http_bearer_jwt.openapi.json
```

## Output

The CLI provides detailed reports on any vulnerabilities detected during the scan. Below is an example of the output format:

| TECHNOLOGIE/SERVICE |     VALUE     |
|---------------------|---------------|
| Framework           | Flask:2.2.3   |
| Language            | Python:3.11.9 |
| Server              | Flask:2.2.3   |


Advice: There are some low-risk issues. It's advised to take a look.

|          OPERATION           | RISK LEVEL | CVSS 4.0 SCORE |             OWASP              |         VULNERABILITY          |
|------------------------------|------------|----------------|--------------------------------|--------------------------------|
| GET /                        | Medium     |            5.1 | API8:2023 Security             | X-Frame-Options Header is      |
|                              |            |                | Misconfiguration               | missing                        |
|                              | Medium     |            5.1 | API8:2023 Security             | CORS Headers are missing       |
|                              |            |                | Misconfiguration               |                                |
|                              | Medium     |            5.1 | API8:2023 Security             | CSP frame-ancestors policy is  |
|                              |            |                | Misconfiguration               | not set                        |
|                              | Info       |            0.0 | API8:2023 Security             | X-Content-Type-Options Header  |
|                              |            |                | Misconfiguration               | is missing                     |
|                              | Info       |            0.0 | API8:2023 Security             | Operation May Accepts          |
|                              |            |                | Misconfiguration               | Unauthenticated Requests       |
|                              | Info       |            0.0 | API8:2023 Security             | HSTS Header is missing         |
|                              |            |                | Misconfiguration               |                                |
|                              | Info       |            0.0 | API8:2023 Security             | CSP Header is not set          |
|                              |            |                | Misconfiguration               |                                |
| GET /books/v1                | Medium     |            5.1 | API8:2023 Security             | CSP frame-ancestors policy is  |
|                              |            |                | Misconfiguration               | not set                        |
|                              | Medium     |            5.1 | API8:2023 Security             | X-Frame-Options Header is      |
|                              |            |                | Misconfiguration               | missing                        |
|                              | Medium     |            5.1 | API8:2023 Security             | CORS Headers are missing       |
|                              |            |                | Misconfiguration               |                                |
|                              | Info       |            0.0 | API8:2023 Security             | CSP Header is not set          |
|                              |            |                | Misconfiguration               |                                |
|                              | Info       |            0.0 | API8:2023 Security             | HSTS Header is missing         |
|                              |            |                | Misconfiguration               |                                |
|                              | Info       |            0.0 | API8:2023 Security             | X-Content-Type-Options Header  |
|                              |            |                | Misconfiguration               | is missing                     |
|                              | Info       |            0.0 | API8:2023 Security             | Operation May Accepts          |
|                              |            |                | Misconfiguration               | Unauthenticated Requests 

In this example, each line represents a detected vulnerability, severity level (critical), vulnerability type, affected operation (GET http://localhost:8080/), and a description of the vulnerability.

## Vulnerabilities Detected

All the vulnerabilities detected by the project are listed at this URL: [Vulnerabilities Detected](https://vulnapi.cerberauth.com/docs/vulnerabilities/?utm_source=github&utm_medium=readme).

> More vulnerabilities and best practices will be added in future releases. If you have any suggestions or requests for additional vulnerabilities or best practices to be included, please feel free to open an issue or submit a pull request.

## Proxy Support

The scanner supports proxy configurations for scanning APIs behind a proxy server. To use a proxy, set the `HTTP_PROXY` or `HTTPS_PROXY` environment variables with the proxy URL.

A command arg `--proxy` is also available to specify the proxy URL.

## Additional Options

The VulnAPI may support additional options for customizing scans or output formatting. Run `vulnapi -h` or `vulnapi help` command to view available options and their descriptions.

## Telemetry

The scanner collects anonymous usage data to help improve the tool. This data includes the number of scans performed, number of detected vulnerabilities, and the severity of vulnerabilities. No sensitive information is collected. You can opt-out of telemetry by passing the `--sqa-opt-out` flag.

## Complete CLI Help

To view the complete CLI help, execute the following command:

```bash
vulnapi -h
```

Here is the output of the help command:

```bash
vulnapi

Usage:
  vulnapi [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  jwt         Generate JWT tokens
  scan        API Scan
  serve       Start the server

Flags:
  -h, --help          help for vulnapi
      --sqa-opt-out   Opt out of sending anonymous usage statistics and crash reports to help improve the tool

Use "vulnapi [command] --help" for more information about a command.
```

## Disclaimer

This scanner is provided for educational and informational purposes only. It should not be used for malicious purposes or to attack any system without proper authorization. Always respect the security and privacy of others.

## Thanks

This project used the following open-source libraries:
* [SecLists](https://github.com/danielmiessler/SecLists)
* [projectdiscovery/wappalyzergo](https://github.com/projectdiscovery/wappalyzergo)

## License

This repository is licensed under the [MIT License](https://github.com/cerberauth/vulnapi/blob/main/LICENSE) @ [CerberAuth](https://www.cerberauth.com/). You are free to use, modify, and distribute the contents of this repository for educational and testing purposes.
