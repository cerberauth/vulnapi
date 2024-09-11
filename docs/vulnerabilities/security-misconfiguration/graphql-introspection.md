---
description: GraphQL introspection is a feature that allows clients to query the schema of the server. It can be used to discover the schema and types, but it can also be used by attackers to learn about the server's implementation details and find potential vulnerabilities.
---

# GraphQL Introspection Enabled

<table>
    <tr>
        <th>Severity</th>
        <td>Low</td>
    </tr>
    <tr>
        <th>CVEs</th>
        <td></td>
    </tr>
    <tr>
        <th>Classifications</th>
        <td>
            <ul>
                <li><a href="https://cwe.mitre.org/data/definitions/200.html">CWE-200: Information Exposure</a></li>
            </ul>
        </td>
    </tr>
    <tr>
        <th>OWASP Category</th>
        <td>
            <a href="https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/">OWASP API8:2023 Security Misconfiguration</a>
        </td>
    </tr>
</table>

GraphQL introspection is a feature that allows clients to query the schema of the server. It can be used to discover the schema and types, but it can also be used by attackers to learn about the server's implementation details and find potential vulnerabilities.

## What is the impact?

The potential security impacts of GraphQL introspection are significant and can include:
* **Information Disclosure**: Attackers can use introspection to learn about the server's implementation details, such as the types, fields, and arguments, which can lead to information disclosure and potential security vulnerabilities.
* **Schema Enumeration**: Introspection can be used to enumerate the schema and discover hidden or deprecated fields, which can be leveraged to craft targeted attacks or exploit vulnerabilities.
* **Security Misconfiguration**: Improperly configured introspection can expose sensitive information or internal implementation details, leading to security misconfigurations and potential security risks.
* **Data Exposure**: Introspection can reveal sensitive data structures, such as database tables, fields, or relationships, which can be exploited to access or manipulate data in unauthorized ways.

## How to test?

TODO: add VulnAPI command

## How to remediate?

To remediate GraphQL introspection vulnerabilities, you can take the following steps:
* **Disable Introspection**: Disable introspection in production environments to prevent attackers from querying the schema and discovering sensitive information or potential security vulnerabilities.
* **Limit Access**: Restrict access to introspection queries to authorized users or applications, and ensure that only trusted entities can query the schema and access internal implementation details.

## References

- [GraphQL Introspection](https://graphql.org/learn/introspection/)
- [PortSwigger - GraphQL Introspection enabled](https://portswigger.net/kb/issues/00200512_graphql-introspection-enabled)