---
title: "Steampipe Table: trivy_scan_secret - Query Trivy Scan Secrets using SQL"
description: "Allows users to query Trivy Scan Secrets, providing insights into the vulnerabilities associated with secrets in images."
---

# Table: trivy_scan_secret - Query Trivy Scan Secrets using SQL

Trivy is a simple and comprehensive vulnerability scanner for containers and other artifacts. It is used to scan for vulnerabilities in your applications and infrastructure, providing a detailed overview of potential security issues. With Trivy, you can easily scan your projects for vulnerabilities and get detailed reports.

## Table Usage Guide

The `trivy_scan_secret` table provides insights into the vulnerabilities associated with secrets in images. As a security analyst, explore secret-specific details through this table, including the vulnerabilities, types of secrets, and associated metadata. Utilize it to uncover information about secrets, such as those with high severity vulnerabilities, the types of secrets present, and the verification of vulnerability fixes.

## Examples

### Scan all targets defined in trivy.spc for secrets
Explore all defined targets for potential secrets, enabling a comprehensive security assessment and proactive mitigation of potential risks. This helps in maintaining the integrity and confidentiality of your system.

```sql
select
  *
from
  trivy_scan_secret;
```

### Scan a specific directory for secrets
Explore which secrets are hidden within a specific directory. This can be particularly useful for identifying potential security risks or vulnerabilities.

```sql
select
  *
from
  trivy_scan_secret
where
  artifact_type = 'filesystem'
  and artifact_name = '/Users/jane/.aws';
```

### Scan a specific container image for secrets
Analyze the security of a specific container image by identifying potential hidden secrets. This query is useful in pinpointing vulnerabilities and ensuring secure container configuration.

```sql
select
  *
from
  trivy_scan_secret
where
  artifact_type = 'container_image'
  and artifact_name = 'turbot/steampipe';
```

### Count of secrets by artifact
Analyze the settings to understand the quantity of secrets associated with each artifact. This can help in identifying areas where sensitive information might be excessively used or potentially exposed.

```sql
select
  artifact_type,
  artifact_name,
  count(*)
from
  trivy_scan_secret
group by
  artifact_type,
  artifact_name
order by
  count desc;
```

### Count of secrets by rule
Analyze the distribution of secrets by rule to understand which rules are associated with the most secrets, aiding in the prioritization of security measures.

```sql
select
  rule_id,
  count(*)
from
  trivy_scan_secret
group by
  rule_id
order by
  count desc;
```