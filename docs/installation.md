---
description: Learn how to install VulnAPI.
---

# Installation

You can installed pre-built binaries of VulnAPI on Linux, Windows, and MacOS.

Below are the instructions to install VulnAPI on Linux, Windows, MacOS, and Docker. You can choose the installation method that best suits your needs and environment.

## Linux

### Snap

You can install VulnAPI on Linux using [Snap](https://snapcraft.io/vulnapi).

```bash
sudo snap install vulnapi
```

### APT

Download the latest [VulnAPI release](https://github.com/cerberauth/vulnapi/releases?ref=deb) and install it using `dpkg`.

```bash
sudo dpkg -i vulnapi.deb
```

### RPM

Download the latest [VulnAPI release](https://github.com/cerberauth/vulnapi/releases?ref=rpm) and install it using `dpkg`.

```bash
sudo rpm -i vulnapi.rpm
```

### Other

You can install VulnAPI on Linux by downloading the latest [VulnAPI release](https://github.com/cerberauth/vulnapi/releases?ref=other) and extracting the contents of the ZIP file. After extracting the contents, run the `vulnapi` binary from the command line.

## Windows

You can install VulnAPI on Windows by downloading the latest [VulnAPI release](https://github.com/cerberauth/vulnapi/releases?ref=windows) and extracting the contents of the ZIP file. After extracting the contents, you can run the `vulnapi.exe` binary from the command line.

## MacOS (Homebrew)

You can install VulnAPI on MacOS using Homebrew. To do so, run the following command:

```bash
brew tap cerberauth/vulnapi https://github.com/cerberauth/vulnapi
brew install $(brew --repository cerberauth/vulnapi)/vulnapi.rb
```

## Docker

You can also use VulnAPI as a Docker container with [VulnaAPI Docker Image](https://hub.docker.com/r/cerberauth/vulnapi). To do so, run the following command:

```bash
docker run --rm cerberauth/vulnapi scan curl [API_URL] [CURL_OPTIONS]
```

## GitHub Action

VulnAPI can be integrated into your CI/CD pipeline using [GitHub Actions](./getting-started/github-action.md). Integrating VulnAPI with GitHub Actions enables you to scan your APIs for vulnerabilities and security risks as part of your CI/CD pipeline. This allows you to automate security testing and vulnerability scanning of your APIs as part of your development workflow, ensuring that your APIs are **secure** and free from vulnerabilities **before they are deployed to production**.
