# Documentation

1. [OAuth client setup](./002_oauth_login.md)
1. [API setup](./003_okta_api.md)
1. [Example project configuration](./004_example_project_configuration.md)
1. [Considerations](./099_considerations.md)

## How it works

This module uses the following libraries and Silverstripe vendor modules to provide sign-in via a configured Okta OAuth2 service application.

+ [bigfork/silverstripe-oauth-login](https://github.com/bigfork/silverstripe-oauth-login) + dependencies
+ [foxworth42/oauth2-okta](https://github.com/foxworth42/oauth2-okta), a [league/oauth2-client](https://github.com/thephpleague/oauth2-client) client
+ [okta/sdk](https://github.com/okta/okta-sdk-php)
+ [silverstripe/framework](https://github.com/silverstripe/silverstripe-framework)

Configuring your Okta OAuth service application is outside the scope of this document. [Okta provides good documentation](https://developer.okta.com/docs/guides/implement-oauth-for-okta/create-oauth-app/).

Your service application should provide or be configured with the following:

1. A `Client ID`
1. A `Client secret`
1. An Okta domain (eg. `some-app.oktapreview.com`)
1. Application type: `Web`
1. Grant type: `Client acting on behalf of a user` - `Authorization Code`
1. User consent + URI - your decision
1. Sign-in/Sign-out redirect URIs - add URIs that match the sites you are issuing authentication requests from
1. Login initiated by: choose a selection
1. Initiate login URI. This is a URI a user can visit to initiate an Okta login automatically. Example below

## Sign-in URI

Example: https://mysite.example/oauth/callback

## Sign-out URI

Example: https://mysite.example/Security/logout

### Initiate login URI

An `Initiate login URI` with `openid`, `profile` and `email` scopes should be provided. The Provider value must match the provider `name: 'Okta'` value from configuration. For this module it is `Okta`. If your project modifies this, it needs to be modified in the URI as well:

> https://mysite.example.com/oauth/authenticate/?provider=Okta&context=login&scope%5B0%5D=openid&scope%5B1%5D=profile&scope%5B2%5D=email

Copy the client ID, client secret, Okta domain and Sign-in redirect URI values into [the configuration for your project](./004_example_project_configuration.md)

+ Client ID -> clientId
+ Client Secret -> clientSecret
+ Okta domain -> issuer
+ Sign-in redirect URI -> redirectUri
