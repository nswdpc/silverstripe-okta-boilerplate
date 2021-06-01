<?php

use Foxworth42\OAuth2\Client\Provider\Okta;
use NSWDPC\Authentication\Okta\Client;
use Bigfork\SilverStripeOAuth\Client\Control\Controller;
use Bigfork\SilverStripeOAuth\Client\Factory\ProviderFactory;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Control\Session;
use SilverStripe\Dev\SapphireTest;

/**
 * Run test related to the Okta API using `okta/sdk`
 */
class OAuthTest extends SapphireTest {

    protected $usesDatabase = false;

    protected $autoFollowRedirection = false;

    /**
     * Test that we can create an authentication URL from the Okta configuration
     */
    public function testOktaAuthenticateUrl() {
        $issuer = [
            'host' => 'something.example.com',
            'path' => '/oauth2',
            'scheme' => 'https'
        ];

        $options = [
            'clientId' => 'test-client-id',
            'clientSecret' => 'test-client-id',
            'issuer' => "{$issuer['scheme']}://{$issuer['host']}{$issuer['path']}",
            'redirectUri' => 'https://localhost/oauth2/callback/',
        ];
        $providers = [];
        $providers['OktaTest'] = new Okta( $options );
        $factory = new ProviderFactory();
        $factory->setProviders($providers);

        $provider = $factory->getProvider('OktaTest');

        $this->assertInstanceOf(Okta::class, $provider);

        Injector::inst()->registerService($factory, ProviderFactory::class);

        $this->assertEquals($options['issuer'] . '/v1', $provider->getBaseApiUrl());
        $this->assertEquals($options['issuer'] . '/v1/authorize', $provider->getBaseAuthorizationUrl());
        $this->assertEquals($options['issuer'] . '/v1/token', $provider->getBaseAccessTokenUrl([]));

        $getVars = [
            'provider' => 'OktaTest',
            'context' => 'login',
            'scope' => [
                'openid',
                'profile',
                'email',
                'groups'
            ]
        ];

        $query = http_build_query($getVars);
        print $query . "\n";

        $request = new HTTPRequest(
            'GET',
            'https://localhost/oauth/authenticate/',
            $getVars
        );
        $request->setSession(new Session([]));
        $controller = new Controller();
        $authenticate = $controller->authenticate($request);

        $this->assertInstanceOf(HTTPResponse::class, $authenticate);

        $this->assertEquals(302, $authenticate->getStatusCode());

        $location = $authenticate->getHeader('Location');

        $this->assertNotEmpty($location);

        $parts = parse_url($location);

        $this->assertEquals( $issuer['scheme'], $parts['scheme']);
        $this->assertEquals( $issuer['host'], $parts['host']);
        $this->assertEquals( $issuer['path'] . '/v1/authorize', $parts['path']);
        $this->assertNotEmpty( $parts['query']) ;

        $query = [];
        parse_str($parts['query'], $query);

        $this->assertEquals(implode(" ", $getVars['scope']), $query['scope']);
        $this->assertNotEmpty($query['state']);
        $this->assertNotEmpty($query['response_type']);
        $this->assertNotEmpty($query['approval_prompt']);
        $this->assertEquals($options['clientId'], $query['client_id']);
        $this->assertEquals($options['redirectUri'], $query['redirect_uri']);

    }

    /**
     * Test that we can get a valid redirection response from a fake callback request
     */
    public function testOktaCallbackUrl() {

    }

}
