<?php

namespace NSWDPC\Authentication\Okta\Tests;

use NSWDPC\Authentication\Okta\Client;
use Okta\Client as OktaClient;
use Okta\Utilities\AuthorizationMode;
use SilverStripe\Core\Config\Config;
use SilverStripe\Dev\SapphireTest;
use Symfony\Component\Yaml\Parser as YamlParser;

/**
 * Run test related to the Okta API using `okta/sdk`
 */
class OktaAPITest extends SapphireTest {

    protected $usesDatabase = false;

    /**
     * Test API client creation
     */
    public function testClientCreation() {

        $sample = dirname(__FILE__ ) . '/support/okta.yaml';

        $parser = new YamlParser();
        $parsed = $parser->parse( file_get_contents($sample) );

        Config::modify()->set(
            Client::class,
            'config_file_location',
            $sample
        );

        $client = Client::create();
        $this->assertInstanceOf(OktaClient::class, $client);

        $this->assertEquals($parsed['okta']['client']['token'], $client->getToken());
        $this->assertEquals($parsed['okta']['client']['orgUrl'], $client->getOrganizationUrl());

    }

    /**
     * Test API client creation with additional runtime parameters
     */
    public function testClientCreationWithParameters() {

        $sample = dirname(__FILE__ ) . '/support/okta.yaml';

        $parser = new YamlParser();
        $parsed = $parser->parse( file_get_contents($sample) );

        Config::modify()->set(
            Client::class,
            'config_file_location',
            $sample
        );

        Config::modify()->set(
            Client::class,
            'default_file_location',
            $sample
        );

        $parameters = [
            'token' => 'another-token',
            // Cannot test private key until below is merged
            // https://github.com/okta/okta-sdk-php/commit/2aff341fc00e5734e61c0985554dc318ebaea638
            'authMode' => AuthorizationMode::SSWS,
            'userAgent'  => 'Auth/1.0'
        ];

        $client = Client::create($parameters);

        $this->assertInstanceOf(OktaClient::class, $client);

        $this->assertEquals($parsed['okta']['client']['orgUrl'], $client->getOrganizationUrl());// default file location retained
        $this->assertEquals($parameters['token'], $client->getToken());
        $this->assertEquals($parameters['userAgent'], $client->getIntegrationUserAgent());
        $this->assertInstanceOf(AuthorizationMode::class, $client->getAuthorizationMode());

    }

}
