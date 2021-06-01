# Create an Okta Oauth2 client

Client creation is handled by the `bigfork/silverstripe-oauth-login` module. See [config.yml](../../_config/config.yml) for an example configuration.

You can override this in your own project to provide clientId, clientSecret, scopes and other values.

See [oauth-login.yml](../../_config/oauth-login.yml) for the base configuration.


## Required configuration values

+ `clientId` your Okta clientId for the app in question
+ `clientSecret` your Okta clientSecret for the app in question
+ `redirectUri` one of the "Sign-in redirect URIs" listed in your application (General Settings)
+ `issuer` your Okta URL, in the format `https://my-subdomain.okta.com/oauth2` (or oktapreview.com for sandbox work)

See the [example project configuration](./004_example_project_configuration.md) to see how these values are used.
