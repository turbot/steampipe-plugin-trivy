---
organization: Turbot
category: ["security"]
icon_url: "/images/plugins/turbot/trivy.svg"
brand_color: "#FA582D"
display_name: Trivy
name: trivy
description: Steampipe plugin using Trivy to query advisories, vulnerabilities for containers, code and more.
og_description: Query advisories, vulnerabilities, packages using Trivy with SQL! Open source CLI. No DB required.
og_image: "/images/plugins/turbot/trivy-social-graphic.png"
---

# Trivy + Steampipe

[Steampipe](https://steampipe.io) is an open source CLI to instantly query cloud APIs using SQL.

[Trivy](https://github.com/aquasecurity/trivy) Trivy is a vulnerability/misconfiguration/secret scanner for containers and other artifacts.

Example query:

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
}
```

## Get involved

- Open source: https://github.com/turbot/steampipe-plugin-trivy
- Community: [Slack Channel](https://steampipe.io/community/join)
