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
