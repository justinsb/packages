# per-location

## Description
sample description

## Usage

### Fetch the package
`kpt pkg get REPO_URI[.git]/PKG_PATH[@VERSION] per-location`
Details: https://kpt.dev/reference/cli/pkg/get/

### View package content
`kpt pkg tree per-location`
Details: https://kpt.dev/reference/cli/pkg/tree/

### Apply the package
```
kpt live init per-location
kpt live apply per-location --reconcile-timeout=2m --output=table
```
Details: https://kpt.dev/reference/cli/live/
