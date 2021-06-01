# Example project configuration

```yaml
---
Name: app-oauth-login
After:
  - '#silverstripe-okta-oauthprovider'
---
SilverStripe\Core\Injector\Injector:
  Bigfork\SilverStripeOAuth\Client\Factory\ProviderFactory:
    properties:
      providers:
        'Okta': '%$OktaProvider'
  OktaProvider:
    class: 'Foxworth42\OAuth2\Client\Provider\Okta'
    constructor:
      Options:
        clientId: 'not-a-client-id'
        clientSecret: 'not-a-client-secret'
        issuer: 'https://something.oktapreview.com/oauth2'
        redirectUri: 'https://mysite.example.com/oauth/callback/'
Bigfork\SilverStripeOAuth\Client\Authenticator\Authenticator:
  providers:
    'Okta':
      # this text appears on the sign-in button
      name: 'Okta'
Bigfork\SilverStripeOAuth\Client\Mapper\GenericMemberMapper:
  mapping:
    'Okta':
      # Map the Member fields to the Okta provider methods eg. getEmail()
      'Email': 'Email'
      'FirstName': 'FirstName'
      'Surname': 'Surname'
---
Name: app-okta-api
After:
  - '#silverstripe-okta-api'
---
# API client options
NSWDPC\Authentication\Okta\Client:
  default_file_location: '/path/to/okta.yaml'
  config_file_location: null
---
Name: app-okta-loginhandler
After:
  - '#silverstripe-okta-loginhandler'
---
# Oauth login handler
NSWDPC\Authentication\Okta\OktaLoginHandler:
  link_existing_member: true
  apply_group_restriction: true
  site_restricted_groups:
    - 'An Okta group the user has to be in'
```
