# Create an Okta Oauth2 client

Client creation is handled by the `bigfork/silverstripe-oauth-login` module. See [oauth-login.yml](../../_config/oauth-login.yml) for an example configuration.

## Authenticator

The module configures and provides an extension to the OAuth authenticator. This authenticator provides a logout handler.

### Turn ON the Member Authenticator

By default, the module resets all authenticators. To enable local user access, add the following environment variable to your project:

```
ALLOW_MEMBER_AUTHENTICATOR=1
```

## Required configuration values

+ `clientId` your Okta clientId for the app in question
+ `clientSecret` your Okta clientSecret for the app in question
+ `redirectUri` one of the "Sign-in redirect URIs" listed in your application (General Settings)
+ `issuer` your Okta URL, in the format `https://my-subdomain.okta.com/oauth2` (or oktapreview.com for sandbox work)

See the [example project configuration](./004_example_project_configuration.md) to see how these values are used.
