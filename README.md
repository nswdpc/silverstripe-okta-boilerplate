# 🧪 Okta authentication boilerplate

This module adds Okta OAuth2 authentication and group discovery to your Silverstripe website

:warning: 🧪 This module is under active development and may include breaking changes.

## Scope

With this module you can

+ Create an OAuth2 client via configuration using [bigfork/silverstripe-oauth-login](https://github.com/bigfork/silverstripe-oauth-login)
+ Authenticate an Okta user that may or may not be a Silverstripe member, via Okta OAuth
+ Save Okta groups returned for a user as Silverstripe group records, and link that user to them
+ Restrict Silverstripe login access to one or more configured Okta groups
+ Optionally disallow/allow the default member authenticator

### Okta API

+ Create an Okta API client using [okta/sdk](https://github.com/okta/okta-sdk-php)
+ Synchronise users via a queued job (via Okta API)
+ Block sign-in for those Okta users who have stopped appearing for a configured time period in synchronisation results
+ Optionally remove users who have not synchronised after a certain time.

Use of the Okta API is optional.

## You will need

+ An Okta account
+ An Okta OAuth service application configured with scopes granted
+ A valid groups claim to return some or all of the user's Okta groups
+ If you require multiple sites authenticating via Okta, a service application per site.
+ A `clientId` and `clientSecret` for Oauth

### Okta API

+ To work with the Okta API, you will need an Okta API token

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

## TODO

+ Private Key authentication mode

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
