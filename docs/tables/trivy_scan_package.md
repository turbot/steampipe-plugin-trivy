---
title: "Steampipe Table: trivy_scan_package - Query Trivy Scan Packages using SQL"
description: "Allows users to query Trivy Scan Packages, specifically the vulnerabilities associated with each package, providing insights into potential security risks."
---

# Table: trivy_scan_package - Query Trivy Scan Packages using SQL

Trivy is a simple and comprehensive vulnerability scanner for containers. It detects vulnerabilities of OS packages (Alpine, RHEL, CentOS, etc.) and application dependencies (Bundler, Composer, npm, yarn, etc.). Trivy is particularly useful for comprehensively addressing vulnerability management in containerized environments.

## Table Usage Guide

The `trivy_scan_package` table provides insights into the vulnerabilities of packages within Trivy. As a security analyst, explore package-specific details through this table, including the package name, version, and associated vulnerabilities. Utilize it to uncover information about packages, such as those with high vulnerability scores, the source of the vulnerability, and the recommended fix.

## Examples

### Scan all targets defined in trivy.spc for packages
Explore the types of artifacts, their names, and targets in your system to gain insights into their classes, types, and versions. This can help in understanding the overall structure and organization of your system's packages.

```sql+postgres
select
  artifact_type,
  artifact_name,
  target,
  class,
  type,
  name,
  version
from
  trivy_scan_package;
```

```sql+sqlite
select
  artifact_type,
  artifact_name,
  target,
  class,
  type,
  name,
  version
from
  trivy_scan_package;
```

### Scan a specific directory for packages
Explore specific directories to identify the packages present within them. This is useful for understanding the composition and versioning of your software assets.

```sql+postgres
select
  target,
  class,
  type,
  name,
  version
from
  trivy_scan_package
where
  artifact_type = 'filesystem'
  and artifact_name = '/Users/jane/src/steampipe';
```

```sql+sqlite
select
  target,
  class,
  type,
  name,
  version
from
  trivy_scan_package
where
  artifact_type = 'filesystem'
  and artifact_name = '/Users/jane/src/steampipe';
```

### Scan a specific container image for packages
Explore the contents of a specific container image to identify the packages it contains. This is useful for understanding the components of your container image, aiding in maintenance and potential vulnerability management.

```sql+postgres
select
  target,
  class,
  type,
  name,
  version
from
  trivy_scan_package
where
  artifact_type = 'container_image'
  and artifact_name = 'turbot/steampipe';
```

```sql+sqlite
select
  target,
  class,
  type,
  name,
  version
from
  trivy_scan_package
where
  artifact_type = 'container_image'
  and artifact_name = 'turbot/steampipe';
```

### Find all installations of the lodash package
Explore which installations have the lodash package. This can be useful to identify instances where this package is used, helping maintain software consistency and version control across installations.

```sql+postgres
select
  artifact_name,
  artifact_type,
  target,
  class,
  name,
  version
from
  trivy_scan_package
where
  name = 'lodash';
```

```sql+sqlite
select
  artifact_name,
  artifact_type,
  target,
  class,
  name,
  version
from
  trivy_scan_package
where
  name = 'lodash';
```

### Find packages with multiple versions installed inside a single target
Explore instances where multiple versions of the same package are installed within a single target. This is useful to identify potential software conflicts or vulnerabilities due to outdated versions.
For example, Javascript packages may have multiple versions installed through
dependencies. This query will find all of those cases and the versions.


```sql+postgres
select
  *
from (
  select
    artifact_name,
    artifact_type,
    target,
    name,
    count(*),
    array_agg(version)
  from
    trivy_scan_package
  group by
    artifact_type,
    artifact_name,
    target,
    name
  ) as multiversion
where
  count > 1
order by
  count desc;
```

```sql+sqlite
select
  *
from (
  select
    artifact_name,
    artifact_type,
    target,
    name,
    count(*),
    group_concat(version)
  from
    trivy_scan_package
  group by
    artifact_type,
    artifact_name,
    target,
    name
  ) as multiversion
where
  "count(*)" > 1
order by
  "count(*)" desc;
```

### Find packages installed / contained within a single source package
This query helps in identifying the various packages that are installed or contained within a single source package. It's useful for understanding the relationship between different packages and their source, which can be crucial for managing dependencies and ensuring system stability.
For example, an OS package for `pam` will include and install multiple pam
library packages. This query will find all those cases and list the
sub-packages.


```sql+postgres
select
  *
from (
  select
    artifact_name,
    artifact_type,
    target,
    src_name,
    count(*),
    array_agg(name)
  from
    trivy_scan_package
  where
    src_name is not null
  group by
    artifact_type,
    artifact_name,
    target,
    src_name
  ) as multipackage
where
  count > 1
order by
  count desc;
```

```sql+sqlite
select
  *
from (
  select
    artifact_name,
    artifact_type,
    target,
    src_name,
    count(*) as count,
    group_concat(name)
  from
    trivy_scan_package
  where
    src_name is not null
  group by
    artifact_type,
    artifact_name,
    target,
    src_name
  ) 
where
  count > 1
order by
  count desc;
```

### Number of packages installed by type
Explore which types of packages are most commonly installed. This can help you identify the most prevalent package types, allowing you to better understand and manage your system's dependencies.

```sql+postgres
select
  artifact_name,
  artifact_type,
  class,
  type,
  count(*)
from
  trivy_scan_package
group by
  artifact_type,
  artifact_name,
  target,
  class,
  type
order by
  count desc;
```

```sql+sqlite
select
  artifact_name,
  artifact_type,
  class,
  type,
  count(*)
from
  trivy_scan_package
group by
  artifact_type,
  artifact_name,
  target,
  class,
  type
order by
  count(*) desc;
```

### Advisories not fixed as the package was "end-of-life"
Discover the segments that consist of advisories not fixed due to their 'end-of-life' status. This is particularly useful in identifying potential vulnerabilities in your system that may arise from outdated packages.

```sql+postgres
select
  source,
  name,
  key,
  fixed_version
from
  trivy_scan_package
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
  trivy_scan_package
where
  state = 'end-of-life';
```

### Scanned artifacts and the unique targets that contain packages
Explore which unique targets contain packages by analyzing the scanned artifacts. This can be useful for understanding the distribution of packages across different targets.

```sql+postgres
select distinct
  artifact_name,
  artifact_type,
  target
from
  trivy_scan_package;
```

```sql+sqlite
select distinct
  artifact_name,
  artifact_type,
  target
from
  trivy_scan_package;
```