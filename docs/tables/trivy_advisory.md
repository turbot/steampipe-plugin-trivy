---
title: "Steampipe Table: trivy_advisory - Query Trivy Advisories using SQL"
description: "Allows users to query Trivy Advisories, providing detailed information about the vulnerabilities identified by Trivy, a Simple and Comprehensive Vulnerability Scanner for Containers."
---

# Table: trivy_advisory - Query Trivy Advisories using SQL

Trivy is a simple and comprehensive vulnerability scanner for containers. It detects vulnerabilities of OS packages (Alpine, RHEL, CentOS, etc.) and application dependencies (Bundler, Composer, npm, yarn, etc.). Trivy is particularly designed to scan containers, but it can also scan filesystems.

## Table Usage Guide

The `trivy_advisory` table offers insights into the vulnerabilities detected by Trivy. As a security analyst, use this table to explore details about the vulnerabilities, including their severity, vendor status, and related references. This can be instrumental in identifying and mitigating potential security risks in your container environments.

## Examples

### List all advisories
Explore the various advisories available, organized by their source and name. This allows for efficient tracking and management of advisories, ensuring that none are overlooked.

```sql+postgres
select
  source,
  name,
  key
from
  trivy_advisory
order by
  source,
  name,
  key;
```

```sql+sqlite
select
  source,
  name,
  key
from
  trivy_advisory
order by
  source,
  name,
  key;
```

### Count of advisories by source
Determine the areas in which security advisories originate to understand where the most vulnerabilities are found. This helps in prioritizing security measures and resources effectively.

```sql+postgres
select
  source,
  count(*)
from
  trivy_advisory
group by
  source
order by
  count desc;
```

```sql+sqlite
select
  source,
  count(*)
from
  trivy_advisory
group by
  source
order by
  count(*) desc;
```

### All advisories for xen
Uncover the details of all advisories related to 'xen' to ensure system vulnerabilities are addressed. This allows for a comprehensive review of potential security risks and the necessary steps to mitigate them.

```sql+postgres
select
  name,
  key,
  source,
  fixed_version
from
  trivy_advisory
where
  name = 'xen'
order by
  name,
  key,
  source,
  fixed_version;
```

```sql+sqlite
select
  name,
  key,
  source,
  fixed_version
from
  trivy_advisory
where
  name = 'xen'
order by
  name,
  key,
  source,
  fixed_version;
```

### Advisories not fixed as the package was "end-of-life"
Explore which advisories haven't been resolved due to the package reaching its end-of-life. This can be useful to identify potential security risks that need to be addressed through other means.

```sql+postgres
select
  source,
  name,
  key,
  fixed_version
from
  trivy_advisory
where
  state = 'end-of-life';
```

```sql+sqlite
select
  source,
  name,
  key,
  fixed_version
from
  trivy_advisory
where
  state = 'end-of-life';
```