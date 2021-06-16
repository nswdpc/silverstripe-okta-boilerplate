# Creating an Okta API client

The Okta API can be used to retrieve information about your Okta users. It is not used in the authentication process.

Quick client creation can be done via the Client factory. It creates an \Okta\Client based on the Silverstripe project configuration provided. You can optionally pass your own HttpClient and/or CacheManager instance

```php
<?php

use NSWDPC\Authentication\Okta\ClientFactory;

$parameters = [];
/* @var \Okta\Client */
$client = ClientFactory::create($parameters);
// Specify http client (\Http\Client\HttpClient) and/or a cache manager (\Okta\Cache\CacheManager)
// $client = ClientFactory::create($parameters, $httpClient, $cacheManger);

// get a user using the client
$user = new \Okta\Users\User();
// get Bob via their Okta userId
$bob = $user->get('75948498674568954');
```

You can also create the `\Okta\Client` via the `\Okta\ClientBuilder` directly ([instructions](https://github.com/okta/okta-sdk-php))

## Parameters

An array of parameters passed to the ClientBuilder. These can be used to modify values on the client prior to client creation.

```php
<?php
$parameters = [
    'authMode' => 'one of the AuthorizationMode values', //@var string
    'clientId' => 'client_id', //@var string
    'privateKey' => 'privateKey', //@var string (not a file path)
    'scopes' => 'scopes', //@var string space separated Okta API scopes
    'token' => 'token', //@var string API token
    'orgUrl' => 'http://some.okta.example.com/', //@var string
    'userAgent' => 'MyUserAgent/1.0', //@var string
];
```

## Configuration

If no configuration is provided `~/.okta/okta.yaml` and/or environment variables will be used.

### okta.yaml

The following format can be used as an example. Supported values are listed in the [Okta PHP SDK ClientBuilder.php](https://github.com/okta/okta-sdk-php/blob/develop/src/ClientBuilder.php#L287)

```yaml
okta:
  client:
     # Your API token
    token: <string>
    # your Okta ORG URL
    orgUrl: <string>
    # clientId
    clientId: <string>
    # scopes
    scopes: <string>|<array>
    # private key
    privateKey: <string>|<absolute file path>
    # optional proxy configuration
    proxy:
      port: <int>
      host: <string>
      username: <string>
      password: <string>
```

### Environment variables

You can also use environment variables if `~/.okta/okta.yaml` does not exist or you wish to override the YAML settings
https://github.com/okta/okta-sdk-php/blob/develop/src/ClientBuilder.php#L330

```shell
OKTA_CLIENT_TOKEN: <string>
OKTA_CLIENT_ORGURL: <string>
OKTA_CLIENT_CLIENTID: <string>
OKTA_CLIENT_SCOPES: <string>
OKTA_CLIENT_PRIVATEKEY: <string> # file path not supported in ENV
OKTA_CLIENT_CONNECTIONTIMEOUT: <int> # of seconds
OKTA_CLIENT_PROXY_PORT: <int>
OKTA_CLIENT_PROXY_HOST: <string>
OKTA_CLIENT_PROXY_USERNAME: <string>
OKTA_CLIENT_PROXY_PASSWORD: <string>
```

## Specific configuration

If you have a requirement to do so, you can configure a different default `okta.yaml` location:

```yaml
---
Name: app-okta-config
After:
    - '#silverstripe-okta-boilerplate'
---
NSWDPC\Authentication\Okta\ClientFactory:
  default_file_location: '/another/path/to/okta.yaml'
```

You can override the default configuration on a selective basis:

```yaml
---
Name: app-okta-config
After:
    - '#silverstripe-okta-boilerplate'
---
NSWDPC\Authentication\Okta\ClientFactory:
  config_file_location: '/specific/okta.yaml'
```

The configuration precedence, based on the `\Okta\ClientBuilder` convention when creating a `\Okta\Client` is:

1. The `~/.okta/okta.yaml`, if available
1. The `NSWDPC\Authentication\Okta\ClientFactory.default_file_location`, if available
1. The OKTA_CLIENT_* environment variables, if set
1. Either
  1. The `NSWDPC\Authentication\Okta\ClientFactory.config_file_location`, if available OR
  1. The `$parameters` passed to `NSWDPC\Authentication\Okta\ClientFactory::create($parameters)`

> Note: parameters and config_file_location are mutually exclusive

Of course, if you set your own configuration location, ensure that it is not in the public web root and that permissions to the configuration file are set appropriately.
