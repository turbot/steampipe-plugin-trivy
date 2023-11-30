---
title: "Steampipe Table: trivy_scan_artifact - Query OCI Trivy Scan Artifacts using SQL"
description: "Allows users to query Trivy Scan Artifacts, specifically the vulnerabilities within the scanned artifacts, providing insights into potential security risks."
---

# Table: trivy_scan_artifact - Query OCI Trivy Scan Artifacts using SQL

Trivy is a simple and comprehensive vulnerability scanner for containers. It detects vulnerabilities in OS packages (Alpine, RHEL, CentOS, etc.) and application dependencies (Bundler, Composer, npm, yarn, etc.). Trivy is easy to use, just install the binary and you're ready to scan.

## Table Usage Guide

The `trivy_scan_artifact` table provides insights into the vulnerabilities of scanned artifacts within OCI Trivy. As a security analyst, explore artifact-specific details through this table, including the types of vulnerabilities, their severities, and associated metadata. Utilize it to uncover information about potential security risks and to assist in prioritizing remediation efforts.

## Examples

### List the target artifacts as defined in trivy.spc
Discover the types of target artifacts as defined in your system, which can help in understanding the different components involved and their nature. This can be beneficial in managing and organizing your resources effectively.

```sql
select
  artifact_name,
  artifact_type
from
  trivy_scan_artifact;
```

### OS for container image artifacts
Analyze the settings to understand the operating system family and name for container image artifacts. This assists in assessing the compatibility and requirements of different systems in your infrastructure.

```sql
select
  artifact_name,
  metadata -> 'OS' ->> 'Family' as family,
  metadata -> 'OS' ->> 'Name' as name
from
  trivy_scan_artifact
where
  artifact_type = 'container_image';
```

### Environment variables for container image artifacts
Analyze the environment variables associated with container image artifacts to gain insights into their configurations. This can be useful for understanding the settings of your container images, which can help in troubleshooting or optimizing their performance.

```sql
select
  artifact_name,
  jsonb_array_elements_text(metadata -> 'ImageConfig' -> 'config' -> 'Env') as env_var
from
  trivy_scan_artifact
where
  artifact_type = 'container_image';
```

### Exposed ports for container image artifacts
Discover the segments that have exposed ports within your container image artifacts. This query is useful for identifying potential security risks and ensuring proper configuration.

```sql
select
  artifact_name,
  port
from
  trivy_scan_artifact,
  jsonb_object_keys(metadata -> 'ImageConfig' -> 'config' -> 'ExposedPorts') as port
where
  artifact_type = 'container_image';
```

### Get full metadata and scan results for every artifact
Explore the comprehensive metadata and scan outcomes for all artifacts to better understand the security vulnerabilities present. This can aid in identifying potential risks and taking proactive measures to mitigate them.
This scan data is more convenient to access through other `trivy_scan_*`
tables, but is provided here for deeper analysis if required.


```sql
select
  artifact_name,
  artifact_type,
  jsonb_pretty(results)
from
  trivy_scan_artifact;
```