# Table: trivy_advisory

Advisories detail the vulnerabilities affecting specific operating systems and packages.

## Examples

### List all advisories

```sql
select
  source,
  name,
  key
from
  trivy_advisory
order by
  source,
  name,
  key
```

### Count of advisories by source

```sql
select
  source,
  count(*)
from
  trivy_advisory
group by
  source
order by
  count desc
```

### All advisories for xen

```sql
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
  fixed_version
```

### Advisories not fixed as the package was "end-of-life"

```sql
select
  source,
  name,
  key,
  fixed_version
from
  trivy_advisory
where
  state = 'end-of-life'
```
