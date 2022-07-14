# Table: trivy_scan_package

Scan files and images for OS and language package versions.

## Examples

### Scan all targets defined in trivy.spc for packages

```sql
select
  artifact_type,
  artifact_name,
  target,
  class,
  type,
  name,
  version
from
  trivy_scan_package
```

### Scan a specific directory for packages

```sql
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
  and artifact_name = '/Users/jane/src/steampipe'
```

### Scan a specific container image for packages

```sql
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
  and artifact_name = 'turbot/steampipe'
```

### Find all installations of the lodash package

```sql
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
  name = 'lodash'
```

### Find packages with multiple versions installed inside a single target

For example, Javascript packages may have multiple versions installed through
dependencies. This query will find all of those cases and the versions.

```sql
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
  count desc
```

### Find packages installed / contained within a single source package

For example, an OS package for `pam` will include and install multiple pam
library packages. This query will find all those cases and list the
sub-packages.

```sql
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
  count desc
```

### Number of packages installed by type

```sql
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
  count desc
```

### Advisories not fixed as the package was "end-of-life"

```sql
select
  source,
  name,
  key,
  fixed_version
from
  trivy_scan_package
where
  state = 'end-of-life'
```

### Scanned artifacts and the unique targets that contain packages

```sql
select distinct
  artifact_name,
  artifact_type,
  target
from
  trivy_scan_package
```
