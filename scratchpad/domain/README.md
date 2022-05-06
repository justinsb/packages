# domain

## Description
sample description

## Usage

### Fetch the package
`kpt pkg get REPO_URI[.git]/PKG_PATH[@VERSION] domain`
Details: https://kpt.dev/reference/cli/pkg/get/

### View package content
`kpt pkg tree domain`
Details: https://kpt.dev/reference/cli/pkg/tree/

### Apply the package
```
kpt live init domain
kpt live apply domain --reconcile-timeout=2m --output=table
```
Details: https://kpt.dev/reference/cli/live/
