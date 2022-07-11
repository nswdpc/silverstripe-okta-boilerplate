<?php

namespace NSWDPC\Authentication\Okta\Tests;

use Bigfork\SilverStripeOAuth\Client\Model\Passport;
use Bigfork\SilverStripeOAuth\Client\Control\Controller;
use Bigfork\SilverStripeOAuth\Client\Factory\ProviderFactory;
use Foxworth42\OAuth2\Client\Provider\Okta;
use Foxworth42\OAuth2\Client\Provider\OktaUser;
use GuzzleHttp\ClientInterface;
use League\OAuth2\Client\Token\AccessToken;
use Mockery;
use NSWDPC\Authentication\Okta\ClientFactory;
use NSWDPC\Authentication\Okta\OktaLoginHandler;
use NSWDPC\Authentication\Okta\OktaLinker;
use NSWDPC\Authentication\Okta\GroupExtension;
use NSWDPC\Authentication\Okta\OAuthLog;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
use SilverStripe\Control\Controller as SilverstripeController;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Control\Session;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Group;
use SilverStripe\Security\Member;
use SilverStripe\Security\RequestAuthenticationHandler;
use SilverStripe\Security\Security;

/**
 * OAuth (Okta) tests
 */
class OAuthTest extends SapphireTest
{

    /**
     * @inheritdoc
     */
    protected $usesDatabase = true;

    /**
     * @inheritdoc
     */
    protected $autoFollowRedirection = false;

    /**
     * @var array
     */
    protected $rootOktaGroup = [
        'Code' => 'okta-root-test',
        'Title' => 'Okta test group',
        'Description' => 'This is the parent group for all groups imported from Okta - testing',
        'IsOktaGroup' => 1,
        'Locked' => 1
    ];

    /**
     * Log out the currently signed in user, if any, before any tests
     */
    protected function setUp() : void
    {
        Config::modify()->set(
            Group::class,
            'okta_group',
            $this->rootOktaGroup
        );
        parent::setUp();
        $this->logOut();
    }

    /**
     * Get an Access Token
     */
    protected function getAccessToken($options = []) : AccessToken
    {
        return new AccessToken($options);
    }

    /**
     * Return issuer URI parts
     */
    protected function getIssuer() : array
    {
        $issuer = [
            'host' => 'something.example.com',
            'path' => '/oauth2',
            'scheme' => 'https'
        ];
        return $issuer;
    }

    public function testGroupCodeChange() {

        $code = 'test';

        $group = Group::create([
            'Title' => 'Test',
            'Code' => $code,
            'Description' => 'Testing group'
        ]);

        $group->write();

        $this->assertEquals($code, $group->Code);

        $groupSaved = Group::get()->filter( [ 'Code' => $code ] )->first();

        $this->assertEquals($code, $groupSaved->Code);

        $groupSaved->setField('Code', $code);

        $this->assertEquals($code, $groupSaved->Code);

        $groupSaved->write();

        $this->assertEquals($code, $groupSaved->Code);

    }

    public function testApplyOktaRootGroup() {

        $parent = Group::config()->get('okta_group');

        /** @var Group **/
        $rootOktaGroup = GroupExtension::applyOktaRootGroup();

        $this->assertInstanceOf(Group::class, $rootOktaGroup, "Root Okta Group is a group");
        $this->assertEquals($parent['Code'], $rootOktaGroup->Code, "Codes match");
        $this->assertEquals($parent['Title'], $rootOktaGroup->Title, "Titles match");
        $this->assertEquals(1, $rootOktaGroup->IsOktaGroup, "IsOktaGroup value match");
        $this->assertEquals(0, $rootOktaGroup->ParentID, "ParentID is zero");
        $this->assertEquals(1, $rootOktaGroup->Locked, "Group is locked");
    }

    /**
     * Test that we can create an authentication URL from the Okta configuration
     */
    public function testOktaAuthenticateUrl()
    {
        $issuer = $this->getIssuer();
        $options = [
            'clientId' => 'test-client-id',
            'clientSecret' => 'test-client-secret',
            'issuer' => "{$issuer['scheme']}://{$issuer['host']}{$issuer['path']}",
            'redirectUri' => 'https://localhost/oauth/callback/',
        ];
        $providers = [];
        $providers['OktaTest'] = new Okta($options);
        $factory = Injector::inst()->get(ProviderFactory::class);
        $factory->setProviders($providers);

        $provider = $factory->getProvider('OktaTest');

        $this->assertInstanceOf(Okta::class, $provider);

        Injector::inst()->registerService($factory, ProviderFactory::class);

        $this->assertEquals($options['issuer'] . '/v1', $provider->getBaseApiUrl());
        $this->assertEquals($options['issuer'] . '/v1/authorize', $provider->getBaseAuthorizationUrl());
        $this->assertEquals($options['issuer'] . '/v1/token', $provider->getBaseAccessTokenUrl([]));

        $getVars = [
            'BackURL' => '/',
            'provider' => 'OktaTest',
            'context' => 'login',
            'scope' => [
                'openid',
                'profile',
                'email'
            ]
        ];

        $query = http_build_query($getVars);

        $request = new HTTPRequest(
            'GET',
            'https://localhost/oauth/authenticate/',
            $getVars
        );
        $request->setSession(new Session([]));
        $controller = new Controller();
        $authenticate = $controller->authenticate($request);

        $this->assertInstanceOf(HTTPResponse::class, $authenticate);

        $this->assertEquals(302, $authenticate->getStatusCode(), "Authentication failure should be a 302 redirect");

        $location = $authenticate->getHeader('Location');

        $this->assertNotEmpty($location);

        $parts = parse_url($location);

        $this->assertEquals($issuer['scheme'], $parts['scheme']);
        $this->assertEquals($issuer['host'], $parts['host']);
        $this->assertEquals($issuer['path'] . '/v1/authorize', $parts['path']);
        $this->assertNotEmpty($parts['query']) ;

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
     * Get a user with a 'corret' claim on an email (as in they own the SS member email address)
     */
    protected function getCorrectUser() : array
    {
        return [
            'sub' => "some-okta-user-id",
            'given_name' => "Sandy",
            'family_name' => "Okta-User",
            'name' => "Sandy Okta-User",
            'email' => "sandy.oktauser@example.com",
            'preferred_username' => "sandy.oktauser@example.com"
        ];
    }

    /**
     * Get a user with an invalid claim
     */
    protected function getFailUser() : array
    {
        return [
            'sub' => "some-user-no-username",
            'given_name' => "Fail",
            'family_name' => "User",
            'name' => "Fail User",
            'email' => "fail.user@example.com",
            'preferred_username' => ""
        ];
    }

    /**
     * Get conflicting user, note same email as correct user ^
     */
    protected function getConflictingUser() : array
    {
        return [
            'sub' => "conflicting-okta-user-id",
            'given_name' => "Sandy",
            'family_name' => "NotSandy",
            'name' => "Sandy NotSandy",
            'email' => "sandy.oktauser@example.com",
            'preferred_username' => "sandy.notsandy@example.com"
        ];
    }

    /**
     * Get a user with a bunch of groups to test  group assignment and sync on auth
     */
    protected function getAssignGroupTestUser() : array
    {
        return [
            'sub' => "test-group-user-id",
            'given_name' => "Herman",
            'family_name' => "Gruppe",
            'name' => "Herman Gruppe",
            'email' => "Herman.Gruppe@example.com",
            'preferred_username' => "herman.gruppe@example.com"
        ];
    }

    /**
     * Set a session on the current controller
     * @return void
     */
    protected function setSessionOnController(Session &$session)
    {
        $controller = SilverstripeController::curr();
        $controller->getRequest()->setSession($session);
    }

    /**
     * Return an access token and provider for a supplied user and session
     */
    protected function setupForLoginHandler(Session &$session, array $authenticatingUser, int $expires = 3600)
    {
        $this->setSessionOnController($session);

        $issuer = $this->getIssuer();

        $options = [
            'clientId' => 'test-client-id',
            'clientSecret' => 'test-client-secret',
            'issuer' => "{$issuer['scheme']}://{$issuer['host']}{$issuer['path']}",
            'redirectUri' => 'https://localhost/oauth/callback/',
        ];

        $provider = new Okta($options);

        $stream = Mockery::mock(StreamInterface::class);
        $stream
            ->shouldReceive('__toString')
            ->once()
            ->andReturn(json_encode($authenticatingUser));

        $response = Mockery::mock(ResponseInterface::class);
        $response
            ->shouldReceive('getBody')
            ->once()
            ->andReturn($stream);
        $response
            ->shouldReceive('getHeader')
            ->once()
            ->with('content-type')
            ->andReturn('application/json');

        $client = Mockery::spy(ClientInterface::class, [
            'send' => $response,
        ]);

        $provider->setHttpClient($client);

        $accessToken = $this->getAccessToken([
            'access_token' => 'okta_test_123',
            'expires' => $expires
        ]);

        $user = $provider->getResourceOwner($accessToken);
        $url = $provider->getResourceOwnerDetailsUrl($accessToken);

        $this->assertInstanceOf(OktaUser::class, $user);

        $this->assertEquals(
            $options['issuer'] . "/v1/userinfo",
            $url
        );

        return [
            'accessToken' => $accessToken,
            'provider' => $provider,
        ];
    }

    public function testOktaLoginHandlerFail()
    {
        $session = new Session([]);
        // Fail user has no username
        $result = $this->setupForLoginHandler($session, $this->getFailUser());

        $oauthsource = 'Okta';
        $session->set('oauth2.provider', $oauthsource);

        Config::inst()->set(OktaLinker::class, 'update_existing_member', true);
        Config::inst()->set(OktaLinker::class, 'link_via_email', false);

        $handler = new OktaLoginHandler();
        $response = $handler->handleToken($result['accessToken'], $result['provider']);

        $code = $handler->getLoginFailureCode();

        $this->assertInstanceOf(HTTPResponse::class, $response);

        // the permission failure is a redirect code as not signed in
        $sessionMessage = $session->get('Security.Message.message');
        $sessionMessageType = $session->get('Security.Message.type');

        // assert that the message contains the message id via regex
        $pattern = "/^.+\(#([0-9]+)\)$/s";
        $result = preg_match($pattern, $sessionMessage, $matches);
        $this->assertTrue($result > 0, "Session message should match pattern {$pattern}");
        $this->assertEquals('warning', $sessionMessageType, "Message type should be warning");
        $logRef = $matches[1];

        $log = OAuthLog::get()->filter(['MessageId' => $logRef])->first();
        $this->assertNotNull($log, "Has a log record");
        $this->assertEquals( OktaLoginHandler::FAIL_USER_MISSING_USERNAME, $log->Code, "Log code matches");
    }

    public function testOktaLoginHandlerSuccess()
    {
        $session = new Session([]);
        $user = $this->getCorrectUser();
        $result = $this->setupForLoginHandler($session, $user);

        $oauthsource = 'Okta';
        $session->set('oauth2.provider', $oauthsource);

        Config::inst()->set(OktaLinker::class, 'update_existing_member', true);
        Config::inst()->set(OktaLinker::class, 'link_via_email', false);

        $handler = new OktaLoginHandler();
        $response = $handler->handleToken($result['accessToken'], $result['provider']);

        // null response from login handler = success
        $this->assertNull($response);

        $message = $session->get('Security.Message.message');
        $type = $session->get('Security.Message.type');

        $code = $handler->getLoginFailureCode();

        $this->assertEmpty($message);
        $this->assertNull($code);

        $member = Member::get()->filter(
            [
                'OktaProfileLogin' => $user['preferred_username']
            ]
        )->first();
        $this->assertTrue($member && $member->isInDB(), "Member is in DB");

        // has passport
        $passport = Passport::get()->filter([
            'OAuthSource' => $oauthsource,
            'Identifier' => $user['sub']
        ])->first();

        $this->assertTrue($passport && $passport->isInDB(), "Has a passport");
        $this->assertEquals($passport->MemberID, $member->ID, "Passport member matches");

        // has empty logs
        $logCount = OAuthLog::get()->filter([
            'OAuthSource' => $oauthsource,
            'Identifier' => $user['sub']
        ])->count();
        $this->assertEquals(0, $logCount, "no log records");

        // Member groups
        $this->assertEquals(1, $member->getOktaGroups()->count(), "Has root group" );
    }


    /**
     * That a user with the same email address can't link to current Member
     */
    public function testOktaLoginHandlerConflictingUsers()
    {
        $session = new Session([]);

        $correct = $this->getCorrectUser();
        $result = $this->setupForLoginHandler($session, $correct);

        $oauthsource = 'Okta';
        $session->set('oauth2.provider', $oauthsource);

        Config::inst()->set(OktaLinker::class, 'update_existing_member', true);
        Config::inst()->set(OktaLinker::class, 'link_via_email', false);

        $handler = new OktaLoginHandler();
        $correctResponse = $handler->handleToken($result['accessToken'], $result['provider']);

        $this->assertNull($correctResponse);

        $message = $session->get('Security.Message.message');
        $type = $session->get('Security.Message.type');

        $code = $handler->getLoginFailureCode();

        $this->assertEmpty($message);
        $this->assertNull($code);

        $correctMember = Member::get()->filter('OktaProfileLogin', $correct['preferred_username'])->first();
        $this->assertTrue($correctMember && $correctMember->isInDB());

        $correctPassport = Passport::get()->filter([
            'OAuthSource' => $oauthsource,
            'Identifier' => $correct['sub']
        ])->first();

        $this->assertTrue($correctPassport && $correctPassport->isInDB());
        $this->assertEquals($correctPassport->MemberID, $correctMember->ID);

        // attempt handleToken again with the conflicting user
        $this->logOut();
        $session = new Session([]);
        $session->set('oauth2.provider', $oauthsource);
        $conflicting = $this->getConflictingUser();

        // assert that an email conflict will occur
        $this->assertEquals($conflicting['email'], $correct['email']);

        $result = $this->setupForLoginHandler($session, $conflicting);

        // handle token for user with conflicting email address
        $handler = new OktaLoginHandler();
        $conflictingResponse = $handler->handleToken($result['accessToken'], $result['provider']);

        $this->assertInstanceOf(HTTPResponse::class, $conflictingResponse);
        $this->assertEquals(302, $conflictingResponse->getStatusCode(), "Conflicting response failure should be a 302 redirect");

        $message = $session->get('Security.Message.message');
        $type = $session->get('Security.Message.type');

        $this->assertEquals("warning", $type);

        $conflictingMember = Member::get()->filter('OktaProfileLogin', $conflicting['preferred_username'])->first();
        $this->assertFalse( $conflictingMember && $conflictingMember->isInDB() );

        // check correct passport hasn't changed for correct user
        $postCorrectPassport = Passport::get()->filter([
            'OAuthSource' => $oauthsource,
            'Identifier' => $correct['sub']
        ])->first();
        $this->assertTrue($postCorrectPassport && $postCorrectPassport->isInDB());
        // check member record is linked correctly
        $this->assertEquals($postCorrectPassport->MemberID, $correctMember->ID);

        // check that a passport was created for the conflicting user
        $conflictingPassport = Passport::get()->filter([
            'OAuthSource' => $oauthsource,
            'Identifier' => $conflicting['sub']
        ])->first();
        $this->assertNull($conflictingPassport);

        // check member hasn't changed
        $checkMember = Member::get()->filter('OktaProfileLogin', $correct['preferred_username'])->first();
        $this->assertEquals($checkMember->ID, $correctMember->ID);

    }

    /**
     * Test group assignment
     */
    public function testOktaLoginHandlerGroupAssignment()
    {

        Config::inst()->set(OktaLinker::class, 'update_existing_member', true);
        Config::inst()->set(OktaLinker::class, 'link_via_email', false);

        $session = new Session([]);
        $userWithGroups = $this->getAssignGroupTestUser();

        // create a local Member, assign some groups
        $member = Member::create();
        $member->Email = $userWithGroups['email'];
        $member->OktaProfileLogin = $userWithGroups['preferred_username'];
        $member->write();

        $rootOktaGroup = GroupExtension::applyOktaRootGroup();

        // the member should have no root okta group at this point
        $this->assertEquals(0, $member->getOktaGroups()->count());

        $result = $this->setupForLoginHandler($session, $userWithGroups);

        $oauthsource = 'Okta';
        $session->set('oauth2.provider', $oauthsource);

        Config::inst()->set(OktaLinker::class, 'update_existing_member', true);
        Config::inst()->set(OktaLinker::class, 'link_via_email', false);

        $handler = new OktaLoginHandler();
        $response = $handler->handleToken($result['accessToken'], $result['provider']);

        $this->assertNull($response);

        $message = $session->get('Security.Message.message');
        $type = $session->get('Security.Message.type');

        $code = $handler->getLoginFailureCode();

        // successful sign-in
        $this->assertEmpty($message);
        $this->assertNull($code);

        $postLoginMember = Member::get()->filter('OktaProfileLogin', $userWithGroups['preferred_username'])->first();
        $this->assertTrue($postLoginMember && $postLoginMember->isInDB());
        $this->assertEquals($member->ID, $postLoginMember->ID);

        $this->assertEquals(1, $member->getOktaGroups()->count());
    }

}
