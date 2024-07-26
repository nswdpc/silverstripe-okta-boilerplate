# 🧪 Okta authentication boilerplate

This module adds Okta OAuth2 authentication to your Silverstripe website

:warning: 🧪 This module is under active development and may include breaking changes.

## Scope

With this module you can

+ Create an OAuth2 client via configuration using [bigfork/silverstripe-oauth-login](https://github.com/bigfork/silverstripe-oauth-login)
+ Authenticate an Okta user that may or may not be a Silverstripe member, via Okta OAuth
+ Link a user to an Okta group
+ Optionally disallow/allow the default member authenticator alongside Okta auth

## You will need

+ An Okta account
+ An Okta OAuth service application configured with scopes granted
+ If you require multiple sites authenticating via Okta, a service application per site.
+ A `clientId` and `clientSecret` for OAuth

## Documentation

[Start here](./docs/en/001_index.md) for project setup and configuration examples.

## Requirements

See [composer.json](./composer.json)

## Installation

Via composer:

```shell
composer require nswdpc/silverstripe-okta-boilerplate
```
After installing the module, run a `dev/build` then [start with the documentation](./docs/en/001_index.md).

## License

[BSD-3-Clause](./LICENSE.md)

## Maintainers

+ [dpcdigital@NSWDPC:~$](https://dpc.nsw.gov.au)

## Bugtracker

We welcome bug reports, pull requests and feature requests on the Github Issue tracker for this project.

Please review the [code of conduct](./code-of-conduct.md) prior to opening a new issue.

## Security

If you have found a security issue with this module, please email digital[@]dpc.nsw.gov.au in the first instance, detailing your findings.

## Development and contribution

If you would like to make contributions to the module please ensure you raise a pull request and discuss with the module maintainers.

Please review the [code of conduct](./code-of-conduct.md) prior to completing a pull request.
