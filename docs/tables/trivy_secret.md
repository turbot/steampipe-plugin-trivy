# Table: trivy_secret

Secrets found by scanning the artifacts.

## Examples

### List all secrets

```sql
select
  *
from
  trivy_secret
```

### Count of secrets by artifact

```sql
select
  artifact_type,
  artifact_name,
  count(*)
from
  trivy_secret
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
  trivy_secret
group by
  rule_id
order by
  count desc
```
