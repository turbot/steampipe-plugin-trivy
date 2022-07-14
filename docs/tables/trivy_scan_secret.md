# Table: trivy_scan_secret

Scan files and images for secrets.

## Examples

### Scan all targets defined in trivy.spc for secrets

```sql
select
  *
from
  trivy_scan_secret
```

### Scan a specific directory for secrets

```sql
select
  *
from
  trivy_scan_secret
where
  artifact_type = 'filesystem'
  and artifact_name = '/Users/jane/.aws'
```

### Scan a specific container image for secrets

```sql
select
  *
from
  trivy_scan_secret
where
  artifact_type = 'container_image'
  and artifact_name = 'turbot/steampipe'
```

### Count of secrets by artifact

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
  count desc
```

### Count of secrets by rule

```sql
select
  rule_id,
  count(*)
from
  trivy_scan_secret
group by
  rule_id
order by
  count desc
```
