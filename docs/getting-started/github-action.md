---
description: VulnAPI can be integrated into your CI/CD pipeline using GitHub Actions. This allows you to automate security testing and vulnerability scanning of your APIs as part of your development workflow.
---

# Github Action

VulnAPI can be integrated into your CI/CD pipeline using [GitHub Actions](https://github.com/marketplace/actions/vulnapi-action). Integrating VulnAPI with GitHub Actions enables you to scan your APIs for vulnerabilities and security risks as part of your CI/CD pipeline. 

This allows you to automate security testing and vulnerability scanning of your APIs as part of your development workflow, ensuring that your APIs are **secure** and free from vulnerabilities **before they are deployed to production**.

## Example Workflow

Here's an example of a GitHub Actions workflow that uses VulnAPI to scan your API for vulnerabilities:

```yaml
name: VulnAPI

on: [push]

permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: VulnAPI
        uses: cerberauth/vulnapi-action@v1
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          curl: 'curl http://localhost:8080 -H "Authorization: Bearer eyJhbGci..."'
```

## Documentation

For more information on how to use VulnAPI with GitHub Actions, please refer to the [VulnAPI GitHub Action](https://github.com/marketplace/actions/vulnapi-action) on GitHub Marketplace.
