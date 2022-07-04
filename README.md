![image](https://hub.steampipe.io/images/plugins/turbot/trivy-social-graphic.png)

# Trivy Plugin for Steampipe

Use SQL to query advisories, vulnerabilities for containers, code and more with [Trivy](https://github.com/aquasecurity/trivy).

- **[Get started →](https://hub.steampipe.io/plugins/turbot/trivy)**
- Documentation: [Table definitions & examples](https://hub.steampipe.io/plugins/turbot/trivy/tables)
- Community: [Slack Channel](https://steampipe.io/community/join)
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

Run a query:

```sql
-- TBD
```

```sh
+----------+-----------------+-------------------------+
| name     | value           | description             |
+----------+-----------------+-------------------------+
| localnet | 192.168.80.0/24 | The 192.168.80 network. |
+----------+-----------------+-------------------------+
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
