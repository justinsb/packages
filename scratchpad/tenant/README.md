# tenant

## Description
sample description

## Usage

### Fetch the package
`kpt pkg get REPO_URI[.git]/PKG_PATH[@VERSION] tenant`
Details: https://kpt.dev/reference/cli/pkg/get/

### View package content
`kpt pkg tree tenant`
Details: https://kpt.dev/reference/cli/pkg/tree/

### Apply the package
```
kpt live init tenant
kpt live apply tenant --reconcile-timeout=2m --output=table
```
Details: https://kpt.dev/reference/cli/live/
