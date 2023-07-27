![image](https://hub.steampipe.io/images/plugins/turbot/trivy-social-graphic.png)

# Trivy Plugin for Steampipe

Use SQL to query advisories, vulnerabilities for containers, code and more with [Trivy](https://github.com/aquasecurity/trivy).

- **[Get started →](https://hub.steampipe.io/plugins/turbot/trivy)**
- Documentation: [Table definitions & examples](https://hub.steampipe.io/plugins/turbot/trivy/tables)
- Community: [Join #steampipe on Slack →](https://turbot.com/community/join)
- Get involved: [Issues](https://github.com/turbot/steampipe-plugin-trivy/issues)

## Quick start

Install the plugin with [Steampipe](https://steampipe.io):

```shell
steampipe plugin install trivy
```

Run steampipe:

```shell
steampipe query
```

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

## Developing

Prerequisites:

- [Steampipe](https://steampipe.io/downloads)
- [Golang](https://golang.org/doc/install)

Clone:

```sh
git clone https://github.com/turbot/steampipe-plugin-trivy.git
cd steampipe-plugin-trivy
```

Build, which automatically installs the new version to your `~/.steampipe/plugins` directory:

```shell
make
```

Configure the plugin:

```shell
cp config/* ~/.steampipe/config
vi ~/.steampipe/config/trivy.spc
```

Try it!

```shell
steampipe query
> .inspect trivy
```

Further reading:

- [Writing plugins](https://steampipe.io/docs/develop/writing-plugins)
- [Writing your first table](https://steampipe.io/docs/develop/writing-your-first-table)

## Contributing

Please see the [contribution guidelines](https://github.com/turbot/steampipe/blob/main/CONTRIBUTING.md) and our [code of conduct](https://github.com/turbot/steampipe/blob/main/CODE_OF_CONDUCT.md). All contributions are subject to the [Apache 2.0 open source license](https://github.com/turbot/steampipe-plugin-prometheus/blob/main/LICENSE).

`help wanted` issues:

- [Steampipe](https://github.com/turbot/steampipe/labels/help%20wanted)
- [Trivy Plugin](https://github.com/turbot/steampipe-plugin-trivy/labels/help%20wanted)
