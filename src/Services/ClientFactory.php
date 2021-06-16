<?php

namespace NSWDPC\Authentication\Okta;

use Http\Client\HttpClient;
use Okta\Cache\CacheManager;
use Okta\ClientBuilder;
use Okta\Utilities\AuthorizationMode;
use SilverStripe\Core\Config\Configurable;

/**
 * Creates an {@link \Okta\Client} using configuration supplied or stored
 */
class ClientFactory
{
    use Configurable;

    /**
     * @var string|null
     * If not provided `~/.okta/okta .yaml` will be used
     */
    private static $default_file_location = null;

    /**
     * @var string|null
     * If not provided $default_file_location will be used
     */
    private static $config_file_location = null;

    /**
     * Factory method to create a client with optional parameters.
     * If no parameters are provided, the authorization mode will be AuthorizationMode::SSWS
     * and use values from the configuration path.
     * AuthorizationMode::SSWS, AuthorizationMode::PRIVATE_KEY
     * @param array $parameters to override relevant default_file_location and ALL config_file_location values
     * @param HttpClient $httpClient specify an alternative HttpClient
     * @param CacheManager $cacheManager specify an alternative CacheManager
     * @return \Okta\Client
     */
    final public static function create($parameters = [], HttpClient $httpClient = null, CacheManager $cacheManager = null) : \Okta\Client
    {
        $defaultFileLocation = self::config()->get('default_file_location');

        if (is_string($defaultFileLocation)) {
            if (!file_exists($defaultFileLocation) || !is_readable($defaultFileLocation)) {
                throw new \Exception("The default file location {$defaultFileLocation} was not found or is not readable");
            }
        }

        // Create client build, user default YAML parser
        $clientBuilder = (new ClientBuilder(null, $defaultFileLocation));

        // the existence of parameters overrides config_file_location values
        if (empty($parameters)) {
            $configFileLocation = self::config()->get('config_file_location');
            if (!is_null($configFileLocation) && !is_string($configFileLocation)) {
                throw new \InvalidArgumentException("The config_file_location provided must be NULL or a string");
            }

            if (is_string($configFileLocation)) {
                if (!file_exists($configFileLocation) || !is_readable($configFileLocation)) {
                    throw new \Exception("The location {$configFileLocation} was not found or is not readable");
                }

                $clientBuilder->setConfigFileLocation($configFileLocation);
            }
        }

        $authMode = $parameters['authMode'] ?? '';
        if ($authMode) {
            $clientBuilder->setAuthorizationMode(new AuthorizationMode($authMode));
        }

        $clientId = $parameters['clientId'] ?? '';
        if ($clientId) {
            $clientBuilder->setClientId($clientId);
        }

        $privateKey = $parameters['privateKey'] ?? '';
        if ($privateKey) {
            $clientBuilder->setPrivateKey($privateKey);
        }

        $scopes = $parameters['scopes'] ?? '';
        if ($scopes) {
            $clientBuilder->setScopes($scopes);
        }

        $token = $parameters['token'] ?? '';
        if ($token) {
            $clientBuilder->setToken($token);
        }

        $orgUrl = $parameters['orgUrl'] ?? '';
        if ($orgUrl) {
            $clientBuilder->setOrganizationUrl($orgUrl);
        }

        $userAgent = $parameters['userAgent'] ?? '';
        if ($userAgent) {
            $clientBuilder->setIntegrationUserAgent($userAgent);
        }

        if ($cacheManager instanceof CacheManager) {
            $clientBuilder->setCacheManager($cacheManager);
        }

        if ($httpClient instanceof HttpClient) {
            $clientBuilder->setHttpClient($httpClient);
        }

        $client = $clientBuilder->build();

        return $client;
    }

}
