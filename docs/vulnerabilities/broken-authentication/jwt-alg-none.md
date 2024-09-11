---
description: Accepting the "none" algorithm in a JSON Web Token (JWT) occurs when a JWT is signed with the "none" algorithm, it means there is no signature, making it easy for attackers to tamper with the token's content without detection.
---

# JWT None Algorithm

<table>
    <tr>
        <th>Severity</th>
        <td>High</td>
    </tr>
    <tr>
        <th>CVEs</th>
        <td>
            <ul>
                <li><a href="https://www.cve.org/CVERecord?id=CVE-2015-9235">CVE-2015-9235</a></li>
                <li><a href="https://www.cve.org/CVERecord?id=CVE-2015-2951">CVE-2015-2951</a></li>
            </ul>
        </td>
    </tr>
    <tr>
        <th>Classifications</th>
        <td>
            <ul>
                <li><a href="https://cwe.mitre.org/data/definitions/345.html">CWE-345: Insufficient Verification of Data Authenticity</a></li>
                <li><a href="https://cwe.mitre.org/data/definitions/327.html">CWE-327: Use of a Broken or Risky Cryptographic Algorithm</a></li>
                <li><a href="https://cwe.mitre.org/data/definitions/20.html">CWE-20: Improper Input Validation</a></li>
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

Accepting the "none" algorithm in a JSON Web Token (JWT) occurs when a JWT is signed with the "none" algorithm, it means there is no signature, making it easy for attackers to tamper with the token's content without detection. This can lead to unauthorized access and data manipulation.

## Example

Here is a valid JWT signed with RS512 algorithm:

```
eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.MnECRBSUQEi8GjiAyWHPhPhhpzCiMLldkq-N_VS-iwI08c4xEVUhT1Xrx9kNGuwusiQuLI3AOBTPwtbdaasQDCOpF0nxxQNKkufJYFds61ooFZfXCuRyXe1yGnXPRzTfgr5YVe9-T8_JDccx5JP70d9hoO4DU4GNYQMvrOQl4xu8DEyyDT2hsjyTbrodVhrV9znMfEBCsYPPLI-Q-HYLquGThPdJe2kBNA-CiLRV6Mwzji67cTd_4P_oUHKXsAxMqVpo-xC2xiVpO2P9X1__uXrRrfiNFUur4B71UMgGYJ2z_cQqwFfSXz9glBIf_-BJU10Rkmyo2ew862d7WsHx8g
```

This decoded JWT contains, this parts:

```json:header
{
  "alg": "RS512",
  "typ": "JWT"
}
```

```json:payload
{
  "sub": "1234567890",
  "iat": 1516239022
}
```

The following JWT is invalid but is wrongly authorized when the implementation is vulnerable to this attack.

```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.
```

Invalid JWT has this header with algorithm set to none.

```json
{
  "alg": "none",
  "typ": "JWT"
}
```

## What is the impact?

The potential security impacts of the JWT "alg none" vulnerability are significant and can include:

- **Unauthorized Access**: Attackers can tamper with the JWT payload to modify user roles, permissions, or identifiers, granting them unauthorized access to resources or functionalities within the system.
- **Data Tampering**: Without the signature to ensure integrity, attackers can modify the data within the JWT payload, potentially altering sensitive information such as user details, session parameters, or application state.
- **Impersonation**: Attackers can forge JWTs by crafting their own payloads and presenting them as valid tokens, leading to impersonation attacks where they assume the identity of legitimate users or systems.
- **Privilege Escalation**: Manipulating the JWT payload, attackers may elevate their privileges within the system by granting themselves higher roles or permissions than originally assigned.
- **Replay Attacks**: Attackers can capture and replay valid JWTs since there's no signature validation, allowing them to reuse the tokens to gain unauthorized access or perform malicious actions.
- **Denial of Service (DDoS)**: In some cases, attackers may exploit the vulnerability to craft JWTs with payloads that cause unexpected behavior or errors within the application, potentially leading to service disruptions or system crashes.
- **Bypassing Security Controls**: In systems where JWTs are used for access control (authorization) or authentication, the "alg none" vulnerability can bypass security controls altogether, rendering any security mechanisms relying on JWTs ineffective.

## How to test?

TODO: VulnAPI Command

## How to remediate?

Remediating the JWT "alg none" vulnerability is to ensure that the JWT library or implementation being used is not vulnerable to this issue and is correctly configured.

- **Updating the Library**: Ensure that your JWT library is updated to a version that addresses the "alg none" vulnerability. Check regularly for security updates and patches provided by the library maintainers.
- **Configuration for Algorithm Check**: Configure the JWT library or implementation to enforce checking the algorithm used in the JWT header. Specifically, configure it to reject tokens that are signed using the "none" algorithm. This ensures that only tokens signed with secure algorithms (e.g., HMAC, RSA) are accepted.
