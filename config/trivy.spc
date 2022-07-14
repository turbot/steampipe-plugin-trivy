connection "trivy" {
  plugin = "trivy"

  # Container images to scan by default
  # images = [ "turbot/steampipe", "ubuntu:latest" ]

  # File system paths to scan by default. Must be a full path.
  # paths = [ "/your/code", "/more/of/your/code" ]

  # The Trivy vulnerability database will be saved to the cache location.
  # Defaults to os.TmpDir()/steampipe-plugin-trivy.
  # cache_dir = "/your/cache/dir"
}
