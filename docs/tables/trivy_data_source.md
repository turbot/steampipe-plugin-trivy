---
title: "Steampipe Table: trivy_data_source - Query Container Registry Images using SQL"
description: "Allows users to query Container Registry Images, specifically the vulnerability data for each image, providing insights into potential security risks and exposures."
---

# Table: trivy_data_source - Query Container Registry Images using SQL

A Container Registry Image is a versioned instance of an application, service, or system component, or a set of related services packaged together. These images are stored in the Container Registry, a Docker v2 compliant, private container registry service. The Container Registry supports private Docker namespace creation, image push and pull, and Docker manifest queries.

## Table Usage Guide

The `trivy_data_source` table provides insights into Container Registry Images, specifically their vulnerability data. As a security analyst, explore image-specific details through this table, including the type and severity of vulnerabilities, and associated metadata. Utilize it to uncover information about potential security risks and exposures, such as those with high severity vulnerabilities, the distribution of vulnerabilities, and the verification of security policies.

## Examples

### List all data sources
Explore all the data sources within your system in a structured order for a comprehensive view and better management. This aids in identifying the data origin, ensuring data accuracy, and enhancing overall data governance.

```sql
select
  *
from
  trivy_data_source
order by
  system;
```

### Get a specific data source
Pinpoint the specific locations where a particular data source, such as 'Oracle Linux 6', is being used. This can be beneficial in understanding the scope and impact of that data source within your system.

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
Explore the various data sources related to Alpine Linux in order to understand their systems and associated URLs. This could be beneficial in identifying and managing these resources effectively.

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