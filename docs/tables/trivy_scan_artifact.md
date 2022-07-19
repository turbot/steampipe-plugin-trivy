# Table: trivy_scan_artifact

List all the files and container images that are targeted as artifacts for scanning.

## Examples

### List the target artifacts as defined in trivy.spc

```sql
select
  artifact_name,
  artifact_type
from
  trivy_scan_artifact;
```

### OS for container image artifacts

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
