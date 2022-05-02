# per-environment

## Description
sample description

## Usage

### Fetch the package
`kpt pkg get REPO_URI[.git]/PKG_PATH[@VERSION] per-environment`
Details: https://kpt.dev/reference/cli/pkg/get/

### View package content
`kpt pkg tree per-environment`
Details: https://kpt.dev/reference/cli/pkg/tree/

### Apply the package
```
kpt live init per-environment
kpt live apply per-environment --reconcile-timeout=2m --output=table
```
Details: https://kpt.dev/reference/cli/live/
