---
description: A vulnerability arises when a JSON Web Token (JWT) is signed by the same service but doesn't verify the issuer (the source of the token) and the audience (the intended recipient).
---

# JWT Cross Service Relay Attack

<table>
    <tr>
        <th>Severity</th>
        <td>High</td>
    </tr>
    <tr>
        <th>CVEs</th>
        <td></td>
    </tr>
    <tr>
        <th>Classifications</th>
        <td></td>
    </tr>
    <tr>
        <th>OWASP Category</th>
        <td>
            <a href="https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/">OWASP API2:2023 Broken Authentication</a>
        </td>
    </tr>
</table>

A vulnerability arises when a JSON Web Token (JWT) is signed by the same service but doesn't verify the issuer (the source of the token) and the audience (the intended recipient). This can lead to security risks, as it means an attacker could create a forged JWT with the same service signature and manipulate the issuer and audience fields. Without proper verification, the service may accept the forged token, potentially granting unauthorized access or compromising the system's security.

## Services impacted

TODO: list all the services used to create a token but using the same keys

| Service                                     | Description | Documentation |
| ------------------------------------------- | ----------- | ------------- |
| **Firebase** / **Google Identity Platform** | Firebase provides ID tokens generated from the same key pair. The issuer and audience must be verified to ensure the token has been generated from the expected Firebase Project. | [Firebase Verify Id Token](https://firebase.google.com/docs/auth/admin/verify-id-tokens) |

## Example

TODO: write an example

## How to test?

TODO: VulnAPI Command

## What is the impact?

TODO: write the impact

## How to remediate?

TODO: write the remediation
