---
description: A vulnerability occurs when a JSON Web Token (JWT) is signed with an empty secret. In this scenario, the token lacks proper cryptographic protection, making it susceptible to manipulation.
---

# JWT Blank Secret

<table>
    <tr>
        <th>Severity</th>
        <td>High</td>
    </tr>
    <tr>
        <th>CVEs</th>
        <td>
            <ul>
                <li><a href="https://www.cve.org/CVERecord?id=CVE-2019-20933">CVE-2019-20933</a></li>
                <li><a href="https://www.cve.org/CVERecord?id=CVE-2020-28637">CVE-2020-28637</a></li>
            </ul>
        </td>
    </tr>
    <tr>
        <th>Classifications</th>
        <td>
            <ul>
                <li><a href="https://cwe.mitre.org/data/definitions/287.html">CWE-287: Improper Authentication</a></li>
            </ul>
        </td>
    </tr>
    <tr>
        <th>OWASP Category</th>
        <td>
            <a href="https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/">OWASP API2:2023 Broken Authentication</a>
        </td>
    </tr>
</table>

A vulnerability occurs when a JSON Web Token (JWT) is signed with an empty secret. In this scenario, the token lacks proper cryptographic protection, making it susceptible to manipulation. Attackers can modify the token's claims and content without detection, potentially leading to unauthorized access and data tampering.

## Example

TODO: write an example

## How to test?

TODO: VulnAPI Command

## What is the impact?

TODO: write the impact

## How to remediate?

TODO: write the remediation
