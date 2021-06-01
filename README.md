# Okta authentication boilerplate

This module adds Okta OAuth2 authentication and group+role discovery to your Silverstripe website

> :warning: This module is under active development. Do not use it in production.

## Scope

+ Create an OAuth2 client via configuration using `bigfork/silverstripe-oauth-login`
+ Create an Okta API client using `okta/sdk`
+ Authenticate a user via Okta OAuth
+ Save Okta groups returned for a user as Silverstripe groups
+ Optionally restrict that user via their returned Okta groups

## You will need

+ An Okta account
+ An Okta OAuth service application configured
+ If you require multiple sites authenticating via Okta, a service application per site.
+ A `clientId` and `clientSecret` for Oauth
+ An API key to work with the Okta API

## Documentation

[Start here](./docs/en/001_index.md). We provide project setup and configuration examples.

## Requirements

See composer.json

## Installation

The only support method of installing this module is via composer

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
