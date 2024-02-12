# VulnAPI: An API Security Vulnerability Scanner

## Overview

As APIs are becoming increasingly essential, they are also becoming prime targets for security breaches. To protect your APIs, it's vital to proactively identify and address security vulnerabilities.

VulnAPI is an open-source project designed to help you scan your APIs for common security vulnerabilities and weaknesses. By using this tool, you can detect that some API potential vulnerabilities and fix security issues.

You can test the scanner against example [vulnerability challenges](https://github.com/cerberauth/api-vulns-challenges).

## Documentation

The Vulnerability Scanner CLI offers two methods for scanning APIs:
* **Using Curl-like CLI**: This method involves directly invoking the CLI with parameters resembling curl commands.
* **Using OpenAPI Contracts**: This method utilizes OpenAPI contracts to specify API endpoints for scanning.

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
echo "[JWT_TOKEN]" | vulnapi scan openapi [PATH_TO_OPENAPI_FILE]
```

Replace [PATH_TO_OPENAPI_FILE] with the path to the OpenAPI contract JSON file and [JWT_TOKEN] with the JWT token to use for authentication.

Example:

```bash
echo "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.e30." | vulnapi scan openapi ./test/stub/simple_http_bearer_jwt.openapi.json
```

## Output

The CLI provides detailed reports on any vulnerabilities detected during the scan. Below is an example of the output format:

```bash
2024/02/12 16:09:30 [critical][JWT Alg None] http://localhost:8080/: JWT accepts none algorithm and does verify jwt.
2024/02/12 16:09:30 [critical][JWT Alg None] http://localhost:8080/: JWT accepts none algorithm and does verify jwt.
2024/02/12 16:09:30 [critical][JWT Alg None] http://localhost:8080/resources/ours: JWT accepts none algorithm and does verify jwt.
2024/02/12 16:09:30 [critical][JWT Alg None] http://localhost:8080/resources/those: JWT accepts none algorithm and does verify jwt.
```

In this example, each line represents a detected vulnerability, including the timestamp, severity level (critical), vulnerability type (JWT Alg None), affected endpoint (http://localhost:8080/), and a description of the vulnerability (JWT accepts none algorithm and does not verify JWT).

## Additional Options

The VulnAPI may support additional options for customizing scans or output formatting. Run `vulnapi -h` or `vulnapi help` command to view available options and their descriptions.

## Disclaimer

This scanner is provided for educational and informational purposes only. It should not be used for malicious purposes or to attack any system without proper authorization. Always respect the security and privacy of others.

## License

This repository is licensed under the MIT license License. You are free to use, modify, and distribute the contents of this repository for educational and testing purposes.
