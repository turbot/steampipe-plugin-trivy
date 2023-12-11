---
organization: Turbot
category: ["security"]
icon_url: "/images/plugins/turbot/trivy.svg"
brand_color: "#1904DA"
display_name: Trivy
name: trivy
description: Steampipe plugin using Trivy to query advisories, vulnerabilities for containers, code and more.
og_description: Query advisories, vulnerabilities, packages using Trivy with SQL! Open source CLI. No DB required.
og_image: "/images/plugins/turbot/trivy-social-graphic.png"
engines: ["steampipe", "sqlite", "postgres", "export"]
---

# Trivy + Steampipe

[Steampipe](https://steampipe.io) is an open source CLI to instantly query cloud APIs using SQL.

[Trivy](https://github.com/aquasecurity/trivy) is a vulnerability/misconfiguration/secret scanner for containers and other artifacts.

Scan images or files for vulnerabilities using a query:

```sql
select
  vulnerability_id,
  package_name,
  installed_version,
  title
from
  trivy_scan_vulnerability
where
  artifact_type = 'container_image'
  and artifact_name = 'turbot/steampipe';
```

```sh
+------------------+--------------+-------------------+----------------------------+
| vulnerability_id | package_name | installed_version | title                      |
+------------------+--------------+-------------------+----------------------------+
| CVE-2011-3374    | apt          | 1.8.2.3           | It was found that apt-key… |
| CVE-2022-23218   | libc-bin     | 2.28-10+deb10u1   | glibc: Stack-based buffer… |
| CVE-2022-1304    | e2fsprogs    | 1.44.5-1+deb10u3  | e2fsprogs: out-of-bounds … |
| CVE-2017-18018   | coreutils    | 8.30-3            | coreutils: race condition… |
| CVE-2022-0563    | bsdutils     | 2.33.1-0.1        | util-linux: partial discl… |
+------------------+--------------+-------------------+----------------------------+
```

Or, query the database of vulnerability definitions:

```sql
select
  name,
  published_date,
  title
from
  trivy_vulnerability
where
  name like 'CVE-2022-%'
order by
  name;
```

```sh
+---------------+---------------------------+------------------------------------+
| name          | published_date            | title                              |
+---------------+---------------------------+------------------------------------+
| CVE-2022-0001 | 2022-03-11T13:15:00-05:00 | hw: cpu: intel: Branch History In… |
| CVE-2022-0002 | 2022-03-11T13:15:00-05:00 | hw: cpu: intel: Intra-Mode BTI   … |
| CVE-2022-0005 | 2022-05-12T13:15:00-04:00 | hw: cpu: information disclosure v… |
| CVE-2022-0070 | 2022-04-19T19:15:00-04:00 | <null>                             |
| CVE-2022-0079 | 2022-01-02T22:15:00-05:00 | showdoc is vulnerable to Generati… |
| CVE-2022-0080 | 2022-01-02T07:15:00-05:00 | mruby is vulnerable to Heap-based… |
+---------------+---------------------------+------------------------------------+
```

## Documentation

- **[Table definitions & examples →](/plugins/turbot/trivy/tables)**

## Get started

### Install

Download and install the latest Trivy plugin:

```bash
steampipe plugin install trivy
```

### Configuration

Installing the latest trivy plugin will create a config file (`~/.steampipe/config/trivy.spc`) with a single connection named `trivy`:

```hcl
connection "trivy" {
  plugin = "trivy"

  # Container images to scan by default
  images = [ "turbot/steampipe", "ubuntu:latest" ]

  # File system paths to scan by default. Must be a full path.
  paths = [ "/your/code", "/more/of/your/code" ]
}
```

## Get involved

- Open source: https://github.com/turbot/steampipe-plugin-trivy
- Community: [Join #steampipe on Slack →](https://turbot.com/community/join)
