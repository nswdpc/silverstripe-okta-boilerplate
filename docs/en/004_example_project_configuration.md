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
      'FirstName': 'FirstName'
      'Surname': 'Surname'
---
Name: app-okta-linker
After:
  - silverstripe-okta-linker
---
NSWDPC\Authentication\Okta\OktaLinker:
  update_existing_member: true
```
