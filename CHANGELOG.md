## v1.0.0 [2024-10-22]

There are no significant changes in this plugin version; it has been released to align with [Steampipe's v1.0.0](https://steampipe.io/changelog/steampipe-cli-v1-0-0) release. This plugin adheres to [semantic versioning](https://semver.org/#semantic-versioning-specification-semver), ensuring backward compatibility within each major version.

_Dependencies_

- Recompiled plugin with Go version `1.22`. 
- Recompiled plugin with [steampipe-plugin-sdk v5.10.4](https://github.com/turbot/steampipe-plugin-sdk/blob/develop/CHANGELOG.md#v5104-2024-08-29) that fixes logging in the plugin export tool. 

## v0.4.0 [2023-12-12]

_What's new?_

- The plugin can now be downloaded and used with the [Steampipe CLI](https://steampipe.io/docs), as a [Postgres FDW](https://steampipe.io/docs/steampipe_postgres/overview), as a [SQLite extension](https://steampipe.io/docs//steampipe_sqlite/overview) and as a standalone [exporter](https://steampipe.io/docs/steampipe_export/overview). ([#31](https://github.com/turbot/steampipe-plugin-trivy/pull/31))
- The table docs have been updated to provide corresponding example queries for Postgres FDW and SQLite extension. ([#31](https://github.com/turbot/steampipe-plugin-trivy/pull/31))
- Docs license updated to match Steampipe [CC BY-NC-ND license](https://github.com/turbot/steampipe-plugin-trivy/blob/main/docs/LICENSE). ([#31](https://github.com/turbot/steampipe-plugin-trivy/pull/31))

_Dependencies_

- Recompiled plugin with [steampipe-plugin-sdk v5.8.0](https://github.com/turbot/steampipe-plugin-sdk/blob/main/CHANGELOG.md#v580-2023-12-11) that includes plugin server encapsulation for in-process and GRPC usage, adding Steampipe Plugin SDK version to `_ctx` column, and fixing connection and potential divide-by-zero bugs. ([#30](https://github.com/turbot/steampipe-plugin-trivy/pull/30))

## v0.3.1 [2023-10-05]

_Dependencies_

- Recompiled plugin with [steampipe-plugin-sdk v5.6.2](https://github.com/turbot/steampipe-plugin-sdk/blob/main/CHANGELOG.md#v562-2023-10-03) which prevents nil pointer reference errors for implicit hydrate configs. ([#24](https://github.com/turbot/steampipe-plugin-trivy/pull/24))

## v0.3.0 [2023-10-02]

_Dependencies_

- Upgraded to [steampipe-plugin-sdk v5.6.1](https://github.com/turbot/steampipe-plugin-sdk/blob/main/CHANGELOG.md#v561-2023-09-29) with support for rate limiters. ([#22](https://github.com/turbot/steampipe-plugin-trivy/pull/22))
- Recompiled plugin with Go version `1.21`. ([#22](https://github.com/turbot/steampipe-plugin-trivy/pull/22))

## v0.2.0 [2023-04-07]

_Dependencies_

- Recompiled plugin with [steampipe-plugin-sdk v5.3.0](https://github.com/turbot/steampipe-plugin-sdk/blob/main/CHANGELOG.md#v530-2023-03-16) which includes fixes for query cache pending item mechanism and aggregator connections not working for dynamic tables. ([#12](https://github.com/turbot/steampipe-plugin-trivy/pull/12))

## v0.1.0 [2022-09-09]

_Dependencies_

- Recompiled plugin with [steampipe-plugin-sdk v4.1.6](https://github.com/turbot/steampipe-plugin-sdk/blob/main/CHANGELOG.md#v416-2022-09-02) which includes several caching and memory management improvements. ([#9](https://github.com/turbot/steampipe-plugin-trivy/pull/9))
- Recompiled plugin with Go version `1.19`. ([#9](https://github.com/turbot/steampipe-plugin-trivy/pull/9))

## v0.0.2 [2022-07-21]

_Bug fixes_

- Fixed the brand color. ([#4](https://github.com/turbot/steampipe-plugin-trivy/pull/4))

## v0.0.1 [2022-07-19]

_What's new?_

- New tables added

  - [trivy_advisory](https://hub.steampipe.io/plugins/turbot/trivy/tables/trivy_advisory)
  - [trivy_data_source](https://hub.steampipe.io/plugins/turbot/trivy/tables/trivy_data_source)
  - [trivy_scan_artifact](https://hub.steampipe.io/plugins/turbot/trivy/tables/trivy_scan_artifact)
  - [trivy_scan_package](https://hub.steampipe.io/plugins/turbot/trivy/tables/trivy_scan_package)
  - [trivy_scan_secret](https://hub.steampipe.io/plugins/turbot/trivy/tables/trivy_scan_secret)
  - [trivy_scan_vulnerability](https://hub.steampipe.io/plugins/turbot/trivy/tables/trivy_scan_vulnerability)
  - [trivy_vulnerability](https://hub.steampipe.io/plugins/turbot/trivy/tables/trivy_vulnerability)
