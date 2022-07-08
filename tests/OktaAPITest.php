<?php

namespace NSWDPC\Authentication\Okta\Tests;

use NSWDPC\Authentication\Okta\OktaAppUserSyncJob;
use NSWDPC\Authentication\Okta\ClientFactory;
use Okta\Client as OktaClient;
use Okta\Utilities\AuthorizationMode;
use SilverStripe\Core\Config\Config;
use SilverStripe\Dev\SapphireTest;
use Symfony\Component\Yaml\Parser as YamlParser;

/**
 * Run test related to the Okta API using `okta/sdk`
 */
class OktaAPITest extends SapphireTest
{
    protected $usesDatabase = false;

    public static function setUpBeforeClass() : void
    {
        parent::setUpBeforeClass();

        // turn off default_file_location for these tests
        Config::inst()->update(ClientFactory::class, 'default_file_location', null);

        // set up config file location
        $sample = dirname(__FILE__) . '/support/okta.yaml';
        Config::inst()->update(
            ClientFactory::class,
            'config_file_location',
            $sample
        );
    }

    protected function parseYamlConfig() : array
    {
        $config = Config::inst()->get(
            ClientFactory::class,
            'config_file_location'
        );
        $parser = new YamlParser();
        $parsed = $parser->parse(file_get_contents($config));
        return $parsed;
    }

    /**
     * Test API client creation
     */
    public function testClientCreation()
    {
        $client = ClientFactory::create();
        $this->assertInstanceOf(OktaClient::class, $client);

        $parsed = $this->parseYamlConfig();

        $this->assertEquals($parsed['okta']['client']['token'], $client->getToken());
        $this->assertEquals($parsed['okta']['client']['orgUrl'], $client->getOrganizationUrl());
    }

    /**
     * Test API client creation with additional runtime parameters
     */
    public function testClientCreationWithParameters()
    {
        $parameters = [
            'token' => 'another-token',
            // Cannot test private key until below is merged
            // https://github.com/okta/okta-sdk-php/commit/2aff341fc00e5734e61c0985554dc318ebaea638
            'authMode' => AuthorizationMode::SSWS,
            'userAgent'  => 'Auth/1.0',
            'orgUrl' => 'https://okta.example.com/'
        ];

        $client = ClientFactory::create($parameters);

        $this->assertInstanceOf(OktaClient::class, $client);

        $parsed = $this->parseYamlConfig();

        $this->assertEquals($parameters['orgUrl'], $client->getOrganizationUrl());// default file location retained
        $this->assertEquals($parameters['token'], $client->getToken());
        $this->assertEquals($parameters['userAgent'], $client->getIntegrationUserAgent());
        $this->assertInstanceOf(AuthorizationMode::class, $client->getAuthorizationMode());
    }

    public function testJobCreation() {
        $perPage = 140;
        $unlinkLimit = 90;
        $reportOnly = 1;
        $cursorAfter = '';
        $job = new OktaAppUserSyncJob($perPage, $unlinkLimit, $reportOnly, $cursorAfter);
        $jobData = $job->getJobData();
        $this->assertEquals($perPage, $job->per_page);
        $this->assertEquals($unlinkLimit, $job->unlink_limit);
        $this->assertEquals($reportOnly, $job->report_only);
        $this->assertEquals($cursorAfter, $job->cursor_after);
    }

    public function testJobCreationWithCursorAfter() {
        $perPage = 140;
        $unlinkLimit = 90;
        $reportOnly = 1;
        $cursorAfter = 'some-id-value';
        $job = new OktaAppUserSyncJob($perPage, $unlinkLimit, $reportOnly, $cursorAfter);
        $jobData = $job->getJobData();
        $this->assertEquals($perPage, $job->per_page);
        $this->assertEquals($unlinkLimit, $job->unlink_limit);
        $this->assertEquals($reportOnly, $job->report_only);
        $this->assertEquals($cursorAfter, $job->cursor_after);
    }
}
