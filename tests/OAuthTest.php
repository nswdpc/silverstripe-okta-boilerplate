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
use NSWDPC\Authentication\Okta\Client;
use NSWDPC\Authentication\Okta\OktaLoginHandler;
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

/**
 * Run test related to the Okta API using `okta/sdk`
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
     * Log out the currently signed in user, if any, before any tests
     */
    public function setUp()
    {
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
                'email',
                'groups'
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
            'preferred_username' => "sandy.oktauser",
            'groups' => [
                'everyone',
                'some-group',
                'another-group'
            ]
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
            'preferred_username' => "sandy.notsandy",
            'groups' => [
                'some-group',
                'external-group'
            ]
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
            'preferred_username' => "herman.gruppe",
            'groups' => [
                'group 1',
                'group 10',
                'group 11',
                'group 2',
                'group 3'
            ]
        ];
    }
    
    /**
     * Get a user with a bunch of groups to test  group assignment and sync on auth
     */
    protected function getAssignNoGroupTestUser() : array
    {
        return [
            'sub' => "test-group-user-id",
            'given_name' => "Herman",
            'family_name' => "Keine-Gruppe",
            'name' => "Herman Keine-Gruppe",
            'email' => "Herman.Keine-Gruppe@example.com",
            'preferred_username' => "herman.keine-gruppe",
            'groups' => []
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
    protected function setupForLoginHandler(Session &$session, array $authenticatingUser)
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
            'expires' => 3600
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

    public function testOktaLoginHandlerFailWithRestrictedGroups()
    {
        $session = new Session([]);
        $result = $this->setupForLoginHandler($session, $this->getCorrectUser());

        $oauthsource = 'Okta';
        $session->set('oauth2.provider', $oauthsource);

        // failed the token handling by restricting groups
        $restrictedGroups = [
            'Site group 1'
        ];

        Config::inst()->set(OktaLoginHandler::class, 'link_existing_member', true);
        Config::inst()->set(OktaLoginHandler::class, 'apply_group_restriction', true);
        Config::inst()->set(OktaLoginHandler::class, 'site_restricted_groups', $restrictedGroups);

        $handler = new OktaLoginHandler();
        $response = $handler->handleToken($result['accessToken'], $result['provider']);

        $code = $handler->getLoginFailureCode();
        $this->assertEquals(OktaLoginHandler::FAIL_USER_MISSING_REQUIRED_GROUPS, $code);

        $this->assertInstanceOf(HTTPResponse::class, $response);

        $this->assertEquals(302, $response->getStatusCode(), "Authentication failure should be a 302 redirect");
        $sessionMessage = $session->get('Security.Message.message');
        $sessionMessageType = $session->get('Security.Message.type');
        
        // assert that the message contains the message id via regex
        $pattern = "/^.+\(#([0-9]+)\)$/s";
        $this->assertTrue(preg_match($pattern, $sessionMessage, $matches) > 0, "Session message should match pattern {$pattern}");
        $this->assertEquals('warning', $sessionMessageType);
    }

    public function testOktaLoginHandlerSuccessWithRestrictedGroups()
    {
        $session = new Session([]);
        $result = $this->setupForLoginHandler($session, $this->getCorrectUser());

        $oauthsource = 'Okta';
        $session->set('oauth2.provider', $oauthsource);

        // Restrict the user to this group
        $restrictedGroups = [
            'another-group'
        ];

        Config::inst()->set(OktaLoginHandler::class, 'link_existing_member', true);
        Config::inst()->set(OktaLoginHandler::class, 'apply_group_restriction', true);
        Config::inst()->set(OktaLoginHandler::class, 'site_restricted_groups', $restrictedGroups);

        $handler = new OktaLoginHandler();
        $response = $handler->handleToken($result['accessToken'], $result['provider']);

        $this->assertNull($response);

        $message = $session->get('Security.Message.message');
        $type = $session->get('Security.Message.type');

        $code = $handler->getLoginFailureCode();

        $this->assertEmpty($message);
        $this->assertNull($code);

        $member = Member::get()->filter('Email', 'sandy.oktauser@example.com')->first();
        $this->assertTrue($member && $member->isInDB());

        $passport = Passport::get()->filter([
            'OAuthSource' => $oauthsource,
            'Identifier' => "some-okta-user-id"
        ])->first();

        $this->assertTrue($passport && $passport->isInDB());

        $this->assertEquals($passport->MemberID, $member->ID);
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

        // Restrict the user to this group
        $restrictedGroups = [
            'some-group'
        ];

        Config::inst()->set(OktaLoginHandler::class, 'link_existing_member', true);
        Config::inst()->set(OktaLoginHandler::class, 'apply_group_restriction', true);
        Config::inst()->set(OktaLoginHandler::class, 'site_restricted_groups', $restrictedGroups);

        $handler = new OktaLoginHandler();
        $correctResponse = $handler->handleToken($result['accessToken'], $result['provider']);

        $this->assertNull($correctResponse);

        $message = $session->get('Security.Message.message');
        $type = $session->get('Security.Message.type');

        $code = $handler->getLoginFailureCode();

        $this->assertEmpty($message);
        $this->assertNull($code);

        $correctMember = Member::get()->filter('Email', $correct['email'])->first();
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

        $this->assertEquals($conflicting['email'], $correct['email']);

        $result = $this->setupForLoginHandler($session, $conflicting);

        // handle token for user with conflicting email address
        $handler = new OktaLoginHandler();
        $conflictingResponse = $handler->handleToken($result['accessToken'], $result['provider']);
        $code = $handler->getLoginFailureCode();

        // check correct passport hasn't changed
        $postCorrectPassport = Passport::get()->filter([
            'OAuthSource' => $oauthsource,
            'Identifier' => $correct['sub']
        ])->first();
        $this->assertTrue($postCorrectPassport && $postCorrectPassport->isInDB());
        $this->assertEquals($postCorrectPassport->MemberID, $correctMember->ID);

        // check that a passport was not created for the conflicting user
        $conflictingPassport = Passport::get()->filter([
            'OAuthSource' => $oauthsource,
            'Identifier' => $conflicting['sub']
        ])->first();
        $this->assertTrue(empty($conflictingPassport->ID));

        // check member hasn't changed
        $checkMember = Member::get()->filter('Email', $correct['email'])->first();
        $this->assertEquals($checkMember->ID, $correctMember->ID);

        $this->assertEquals(OktaLoginHandler::FAIL_USER_MEMBER_PASSPORT_MISMATCH, $code);
        $this->assertInstanceOf(HTTPResponse::class, $conflictingResponse);
        $this->assertEquals(302, $conflictingResponse->getStatusCode(), "Authentication failure should be a 302 redirect");
        $sessionMessage = $session->get('Security.Message.message');
        $sessionMessageType = $session->get('Security.Message.type');
        
        // assert that the message contains the message id via regex
        $pattern = "/^.+\(#([0-9]+)\)$/s";
        $this->assertTrue(preg_match($pattern, $sessionMessage, $matches) > 0, "Session message should match pattern {$pattern}");
        $this->assertEquals('warning', $sessionMessageType);
    }

    /**
     * Test group assignment for an authenticating user with groups that intersect the current groups
     */
    public function testOktaLoginHandlerGroupAssignment()
    {
        $session = new Session([]);
        $userWithGroups = $this->getAssignGroupTestUser();
        
        $userGroupCount = count($userWithGroups['groups']);
        $this->assertTrue($userGroupCount > 0, "For this test, the getAssignGroupTestUser test user should have some groups");

        // create a local Member, assign some groups
        $member = Member::create();
        $member->Email = $userWithGroups['email'];
        $member->write();

        $inst = Group::create();
        $rootOktaGroup = $inst->applyOktaRootGroup();

        // current SS groups to create, as Okta linked groups
        $currentSystemGroups = ['group 10','group 11','group 12','group 13'];
        
        $this->assertEquals(
            0,
            $member->getOktaGroups()->count()
        );
        
        // create in DB
        foreach ($currentSystemGroups as $groupTitle) {
            $createdGroup = Group::create([
                'Title' => $groupTitle,
                'IsOktaGroup' => 1,
                'ParentID' => $rootOktaGroup->ID
            ]);
            $createdGroup->write();
            // assign these groups to the member
            // this member previously had 12 and 13
            // member should end up with no group 12, group 13
            $member->Groups()->add($createdGroup);
        }

        // the member should have same okta groups
        $this->assertEquals(count($currentSystemGroups), $member->getOktaGroups()->count());

        $result = $this->setupForLoginHandler($session, $userWithGroups);

        $oauthsource = 'Okta';
        $session->set('oauth2.provider', $oauthsource);

        // Restrict the user to this group post-auth (they can sign in)
        $restrictedGroups = [
            'group 1'
        ];

        Config::inst()->set(OktaLoginHandler::class, 'link_existing_member', true);
        Config::inst()->set(OktaLoginHandler::class, 'apply_group_restriction', true);
        Config::inst()->set(OktaLoginHandler::class, 'site_restricted_groups', $restrictedGroups);

        $handler = new OktaLoginHandler();
        $response = $handler->handleToken($result['accessToken'], $result['provider']);

        $this->assertNull($response);

        $message = $session->get('Security.Message.message');
        $type = $session->get('Security.Message.type');

        $code = $handler->getLoginFailureCode();

        // successful sign-in
        $this->assertEmpty($message);
        $this->assertNull($code);

        $postLoginMember = Member::get()->filter('Email', $userWithGroups['email'])->first();
        $this->assertTrue($postLoginMember && $postLoginMember->isInDB());
        $this->assertEquals($member->ID, $postLoginMember->ID);
        
        $postLoginGroups = $postLoginMember->getOktaGroups();
        
        // the members post login groups should now match the groups present
        $this->assertEquals(
            $userWithGroups['groups'],
            $postLoginGroups->sort('Title')->column('Title'),
            'The Okta groups supplied by the user do not match the post login groups associated with the member'
        );
        
        // all groups should be retained in SS, even if no longer linked to user
        $allOktaGroups = array_unique(array_merge($userWithGroups['groups'], $currentSystemGroups));
        $postLoginSystemGroups = Group::get()->filter(['IsOktaGroup' => 1])->exclude(['ID' => $rootOktaGroup->ID]);
        
        $this->assertEquals(count($allOktaGroups), $postLoginSystemGroups->count());
    }
    
    /**
     * Test handling when a user presents with no groups
     */
    public function testOktaLoginHandlerNoGroupAssignment()
    {
        $session = new Session([]);
        $userWithNoGroups = $this->getAssignNoGroupTestUser();

        // create a local Member, assign some groups
        $member = Member::create();
        $member->Email = $userWithNoGroups['email'];
        $member->write();

        $inst = Group::create();
        $rootOktaGroup = $inst->applyOktaRootGroup();

        // current SS groups to create, as Okta linked groups
        $currentSystemGroups = ['group 20','group 21','group 22','group 23'];
        
        $this->assertEquals(
            0,
            $member->getOktaGroups()->count()
        );
        
        // create in DB
        foreach ($currentSystemGroups as $groupTitle) {
            $createdGroup = Group::create([
                'Title' => $groupTitle,
                'IsOktaGroup' => 1,
                'ParentID' => $rootOktaGroup->ID
            ]);
            $createdGroup->write();
        }

        $result = $this->setupForLoginHandler($session, $userWithNoGroups);

        $oauthsource = 'Okta';
        $session->set('oauth2.provider', $oauthsource);

        // set configuration for no group restriction
        Config::inst()->set(OktaLoginHandler::class, 'link_existing_member', true);
        Config::inst()->set(OktaLoginHandler::class, 'apply_group_restriction', false);
        Config::inst()->set(OktaLoginHandler::class, 'site_restricted_groups', []);

        $handler = new OktaLoginHandler();
        $response = $handler->handleToken($result['accessToken'], $result['provider']);

        $this->assertNull($response);

        $message = $session->get('Security.Message.message');
        $type = $session->get('Security.Message.type');

        $code = $handler->getLoginFailureCode();

        // successful sign-in
        $this->assertEmpty($message);
        $this->assertNull($code);

        $postLoginMember = Member::get()->filter('Email', $userWithNoGroups['email'])->first();
        $this->assertTrue($postLoginMember && $postLoginMember->isInDB());
        $this->assertEquals($member->ID, $postLoginMember->ID);
        
        $postLoginGroups = $postLoginMember->getOktaGroups();
        
        $this->assertEmpty($postLoginGroups->column('Title'));
        
        // the members post login groups should now match the groups present
        $this->assertEquals(
            $userWithNoGroups['groups'],
            $postLoginGroups->sort('Title')->column('Title'),
            'The Okta groups supplied by the user do not match the post login groups associated with the member'
        );
        
        // all groups should be retained in SS, even if no longer linked to user
        $allOktaGroups = array_unique(array_merge($userWithNoGroups['groups'], $currentSystemGroups));
        $postLoginSystemGroups = Group::get()->filter(['IsOktaGroup' => 1])->exclude(['ID' => $rootOktaGroup->ID]);
        
        $this->assertEquals(count($allOktaGroups), $postLoginSystemGroups->count());
    }
}
