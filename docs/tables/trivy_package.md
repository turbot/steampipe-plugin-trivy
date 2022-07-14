# Table: trivy_package

OS and language package versions found in the scanned artifacts.

## Examples

### List all packages

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
  trivy_package
order by
  name,
  version
```

### Find all installations of the lodash package

```sql
select
  artifact_type,
  artifact_name,
  target,
  class,
  name,
  version
from
  trivy_package
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
    artifact_type,
    artifact_name,
    target,
    name,
    count(*),
    array_agg(version)
  from
    trivy_package
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
    artifact_type,
    artifact_name,
    target,
    src_name,
    count(*),
    array_agg(name)
  from
    trivy_package
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
  artifact_type,
  artifact_name,
  target,
  class,
  type,
  count(*)
from
  trivy_package
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
  trivy_package
where
  state = 'end-of-life'
```

### Scanned artifacts and the unique targets that contain packages

```sql
select distinct
  artifact_type,
  artifact_name,
  target
from
  trivy_package
```
