# oinit
> Certificate-based OpenSSH for Federated Identities

[![Latest release](https://img.shields.io/gitlab/v/tag/m-team/oidc/ssh/oinit?gitlab_url=https%3A%2F%2Fcodebase.helmholtz.cloud&sort=semver&color=blue)](https://codebase.helmholtz.cloud/m-team/oidc/ssh/oinit/-/tags)
[![License](https://img.shields.io/badge/license-MIT-blue)](https://github.com/m-team-kit/oinit/blob/main/LICENSE)
[![Gitlab CI](https://codebase.helmholtz.cloud/m-team/oidc/ssh/oinit/badges/main/pipeline.svg)](https://codebase.helmholtz.cloud/m-team/oidc/ssh/oinit/-/pipelines)

This repository contains a collection of programs to enable OpenSSH login for federated identities based on certificates.


<p align="center">
  <img src=".github/oinit.gif" /><br>
  <i>OpenID Connect access token for selected provider is loaded from <a href="https://github.com/indigo-dc/oidc-agent">oidc-agent</a>.</i>
</p>

## Development

```sh
# Client application
$ make oinit

# oinit-shell and oinit-switch
$ make oinit-shell oinit-switch

# Server application (CA)
$ make oinit-ca
```

When changing the REST API annotations, run `make swagger` to generate the Swagger files.

### Branches

Development happens on feature branches checked out from and merged back into `prerel`.
When ready, commits are merged into `main` and tagged as release.


## License

This project is licensed under the [MIT License](LICENSE).
