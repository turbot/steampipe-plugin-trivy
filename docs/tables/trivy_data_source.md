# Table: trivy_data_source

Data sources used for advisories.

## Examples

### List all data sources

```sql
select
  *
from
  trivy_data_source
order by
  system;
```

### Get a specific data source

```sql
select
  system,
  name,
  url
from
  trivy_data_source
where
  name = 'Oracle Linux 6';
```

### List all Alpine Linux data sources

```sql
select
  name,
  system,
  url
from
  trivy_data_source
where
  id = 'alpine'
order by
  name,
  system;
```
