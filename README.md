# VulnAPI: An API Security Vulnerability Scanner

VulnAPI is an Open-Source DAST designed to help you scan your APIs for common security vulnerabilities and weaknesses.

By using this tool, you can detect that some API potential vulnerabilities and fix security issues.

![Demo](demo.gif)

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
+------------+--------------------------------+--------------------------------+----------------------------+
| RISK LEVEL |         VULNERABILITY          |          DESCRIPTION           |         OPERATION          |
+------------+--------------------------------+--------------------------------+----------------------------+
| Critical   | JWT None Algorithm             | JWT with none algorithm is     | GET http://localhost:8080/ |
|            |                                | accepted allowing to bypass    |                            |
|            |                                | authentication.                |                            |
| Low        | CSP Header is not set          | No Content Security Policy     | GET http://localhost:8080/ |
|            |                                | (CSP) Header has been detected |                            |
|            |                                | in HTTP Response.              |                            |
| Low        | CORS Header is not set         | No CORS Header has been        | GET http://localhost:8080/ |
|            |                                | detected in HTTP Response.     |                            |
| Low        | HSTS Header is not set         | No HSTS Header has been        | GET http://localhost:8080/ |
|            |                                | detected in HTTP Response.     |                            |
| Low        | X-Content-Type-Options Header  | No X-Content-Type-Options      | GET http://localhost:8080/ |
|            | is not set                     | Header has been detected in    |                            |
|            |                                | HTTP Response.                 |                            |
| Low        | X-Frame-Options Header is not  | No X-Frame-Options Header      | GET http://localhost:8080/ |
|            | set                            | has been detected in HTTP      |                            |
|            |                                | Response.                      |                            |
| Low        | HTTP Trace Method enabled      | HTTP Trace method seems        | GET http://localhost:8080/ |
|            |                                | enabled for this request.      |                            |
+------------+--------------------------------+--------------------------------+----------------------------+
Warning: Critical vulnerabilities detected!
```

In this example, each line represents a detected vulnerability, severity level (critical), vulnerability type, affected operation (GET http://localhost:8080/), and a description of the vulnerability.

## Vulnerabilities Detected

The scanner is capable of detecting the following vulnerabilities:
* JWT `none` algorithm accepted
* JWT not verified
* JWT blank or weak secret used with HMAC algorithm
* JWT null signature accepted

The scanner also detects the following security best practices:
* CSP Header is not set
* HSTS Header is not set
* CORS Header is not set
* X-Content-Type-Options Header is not set
* X-Frame-Options Header is not set
* HTTP Trace Method enabled
* HTTP Cookies not marked as secure, httpOnly, or SameSite

The scanner perform some discoverability scans:
* Server Signature exposed
* Discovery of API endpoints using OpenAPI contracts
* GraphQL Introspection enabled

> More vulnerabilities and best practices will be added in future releases. If you have any suggestions or requests for additional vulnerabilities or best practices to be included, please feel free to open an issue or submit a pull request.

## Additional Options

The VulnAPI may support additional options for customizing scans or output formatting. Run `vulnapi -h` or `vulnapi help` command to view available options and their descriptions.

## Telemetry

The scanner collects anonymous usage data to help improve the tool. This data includes the number of scans performed, number of detected vulnerabilities, and the severity of vulnerabilities. No sensitive information is collected. You can opt-out of telemetry by passing the `--sqa-opt-out` flag.

## Disclaimer

This scanner is provided for educational and informational purposes only. It should not be used for malicious purposes or to attack any system without proper authorization. Always respect the security and privacy of others.

## Thanks

This project used the following open-source libraries:
* [SecLists](https://github.com/danielmiessler/SecLists)

## License

This repository is licensed under the [MIT License](https://github.com/cerberauth/vulnapi/blob/main/LICENSE) @ [CerberAuth](https://www.cerberauth.com/). You are free to use, modify, and distribute the contents of this repository for educational and testing purposes.
