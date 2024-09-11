---
description: JWT Null Signature vulnerability occurs when a JSON Web Token (JWT) lacks a signature part, allowing attackers to manipulate the token's content.
---

# JWT Null Signature

<table>
    <tr>
        <th>Severity</th>
        <td>High</td>
    </tr>
    <tr>
        <th>CVEs</th>
        <td>
            <ul>
                <li><a href="https://www.cve.org/CVERecord?id=CVE-2020-28042">CVE-2020-28042</a></li>
            </ul>
        </td>
    </tr>
    <tr>
        <th>Classifications</th>
        <td>
            <ul>
                <li><a href="https://cwe.mitre.org/data/definitions/327.html">CWE-327: Use of a Broken or Risky Cryptographic Algorithm</a></li>
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

The "JWT Null Signature" vulnerability occurs when a JSON Web Token (JWT) lacks a signature part, allowing attackers to manipulate the token's content potentially leading to unauthorized access and data tampering.

## Example

TODO: write an example

## How to test?

TODO: VulnAPI Command

## What is the impact?

TODO: write the impact

## How to remediate?

TODO: write the remediation
