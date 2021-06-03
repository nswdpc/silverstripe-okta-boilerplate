<?php
namespace NSWDPC\Authentication\Okta;

use Bigfork\SilverStripeOAuth\Client\Model\Passport;
use Bigfork\SilverStripeOAuth\Client\Handler\LoginTokenHandler;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\ORM\ValidationException;
use SilverStripe\Security\Group;
use SilverStripe\Security\Member;

/**
 * Perform Okta login handling without user/member Email collisions
 */
class OktaLoginHandler extends LoginTokenHandler
{

    use Configurable;

    /**
     * @var bool
     * If true, link to an existing member based on Email address
     * Note: this assumes that the owner of the Okta email address is the owner of
     * the Silvertripe Member.Email address
     * If you cannot ensure that, set this value in your project configuration to false
     */
    private static $link_existing_member = true;

    /**
     * @var bool
     * If true, after authentication the user's Okta groups will be used to determine
     * authenticated access
     * see self::assignGroups() for group scope and return setup
     */
    private static $apply_group_restriction = true;

    /**
     * @var array
     * The user must be in all groups listed here to gain authenticated access to the site
     * If empty then all users authenticating via OAuth can gain access
     */
    private static $site_restricted_groups = [];

    /**
     * List of failure codes
     */
    const FAIL_USER_NO_GROUPS = 100;
    const FAIL_USER_MEMBER_COLLISION = 101;
    const FAIL_USER_MISSING_REQUIRED_GROUPS = 102;
    const FAIL_USER_MISSING_EMAIL = 103;
    const FAIL_USER_MEMBER_EMAIL_MISMATCH = 104;
    const FAIL_USER_MEMBER_PASSPORT_MISMATCH = 105;
    const FAIL_NO_PROVIDER_NAME = 200;
    const FAIL_NO_PASSPORT_NO_MEMBER_CREATED = 300;
    const FAIL_PASSPORT_NO_MEMBER_CREATED = 301;

    /*
     * @var string|null
     */
    protected $loginFailureCode = null;

    /*
     * @var int|null
     */
    protected $loginFailureMessageId = null;

    /**
     * @inheritdoc
     */
    public function handleToken(AccessToken $token, AbstractProvider $provider)
    {
        $this->setLoginFailureCode(null);//reset failure code on new attempt
        return parent::handleToken($token, $provider);
    }

    /**
     * Return message related to code
     */
    public static function getFailMessageForCode($code) : string {
        switch($code) {
            case self::FAIL_USER_NO_GROUPS:
                return _t('OAUTH.FAIL_' . $code, 'User has no Okta groups');
                break;
            case self::FAIL_USER_MEMBER_COLLISION:
                return _t('OAUTH.FAIL_' . $code, 'User/member collision');
                break;
            case self::FAIL_USER_MISSING_REQUIRED_GROUPS:
                return _t('OAUTH.FAIL_' . $code, 'User missing required groups');
                break;
            case self::FAIL_USER_MISSING_EMAIL:
                return _t('OAUTH.FAIL_' . $code, 'User missing email');
                break;
            case self::FAIL_USER_MEMBER_EMAIL_MISMATCH:
                return _t('OAUTH.FAIL_' . $code, 'User/member email mismatch');
                break;
            case self::FAIL_USER_MEMBER_PASSPORT_MISMATCH:
                return _t('OAUTH.FAIL_' . $code, 'User/member/passport mismatch');
                break;
            case self::FAIL_NO_PROVIDER_NAME:
                return _t('OAUTH.FAIL_' . $code, 'No provider name');
                break;
            case self::FAIL_NO_PASSPORT_NO_MEMBER_CREATED:
                return _t('OAUTH.FAIL_' . $code, 'No passport found and no member created');
                break;
            case self::FAIL_PASSPORT_NO_MEMBER_CREATED:
                return _t('OAUTH.FAIL_' . $code, 'Passport created but no member found');
                break;
            default:
                return _t('OAUTH.FAIL_UNKNOWN_CODE', 'Unknown');
                break;
        }
    }

    /**
     * @param string|null $code
     */
    protected function setLoginFailureCode($code, $userId = '') {
        $messageId = null;
        if($code) {
            // a random message id a user can quote to support
            $messageId = random_int(100000,1000000);
            $session = $this->getSession();
            $providerName = $session->get('oauth2.provider');
            OAuthLog::add(
                $code,
                $messageId,
                $providerName,
                $userId
            );
        }
        $this->loginFailureMessageId = $messageId;
        $this->loginFailureCode = $code;
    }

    /**
     * @return string|null
     */
    public function getLoginFailureCode() {
        return $this->loginFailureCode;
    }

    /**
     * @return int|null
     */
    public function getLoginFailureMessageId() {
        return $this->loginFailureMessageId;
    }

    /**
     * Generic support message
     * @return string
     */
    public function getSupportMessage() : string {
        return _t(
            'OAUTH.SUPPORT_MESSAGE',
            'Sorry, there was an issue signing you in. Please try again or contact support.'
        );
    }

    /**
     * Given an identifier and a provider string, return the Passport matching
     * @return Passport|null
     */
    protected function getPassport(string $identifier, string $provider) {
        $passport = Passport::get()->filter([
            'Identifier' => $identifier,
            'OAuthSource' => $provider
        ])->first();
        return $passport;
    }

    /**
     * Get the passport for a provider/member combination
     * @return Passport|null
     */
    protected function getMemberPassport(Member $claimedMember, string $provider) {
        $passport = Passport::get()->filter([
            'MemberID' => $claimedMember->ID,
            'OAuthSource' => $provider
        ])->first();
        return $passport;
    }

    /**
     * Given an identifier and a provider string, create a passport
     * @return Passport|null
     */
    protected function createPassport(string $identifier, string $provider) : Passport {
        $passport = Passport::create([
            'Identifier' => $identifier,
            'OAuthSource' => $provider
        ]);
        $passport->write();
        if(!$passport->isInDB()) {
            return null;
        } else {
            return $passport;
        }
    }

    /**
     * Apply configured group restrictions based on Okta groups returned
     * Returns false when no restriction applied due to configuration, true if user passes checks
     * throw ValidationException if check fails
     * @return bool
     * @throws ValidationException
     * @todo move to Okta control panel in /admin area
     */
    protected function applyOktaGroupRestriction(ResourceOwnerInterface $user) {

        // check if restricting
        if(!$this->config()->get('apply_group_restriction')) {
            return false;
        }

        // get user Okta groups (titles)
        $data = $user->toArray();
        if(empty($data['groups']) || !is_array($data['groups'])) {
            $this->setLoginFailureCode(self::FAIL_USER_NO_GROUPS, $user->getId());
            throw new ValidationException(
                _t(
                    'OKTA.GENERAL_SESSION_ERROR',
                    '{getSupportMessage} (#{messageId})',
                    [
                        'messageId' => $this->getLoginFailureMessageId(),
                        'getSupportMessage' => $this->getSupportMessage()
                    ]
                )
            );
        }

        // User group check
        $restrictedGroups = $this->config()->get('site_restricted_groups');

        if(empty($restrictedGroups)) {
            // no restrictions
            return true;
        }

        if(!is_array($restrictedGroups)) {
            // assume a single group
            $restrictedGroups = [ $restrictedGroups ];
        }

        $intersect = array_intersect($restrictedGroups, $data['groups']);
        // the intersect must contain all the restricted groups
        if($intersect != $restrictedGroups) {
            $this->setLoginFailureCode(self::FAIL_USER_MISSING_REQUIRED_GROUPS, $user->getId());
            throw new ValidationException(
                _t(
                    'OKTA.GENERAL_SESSION_ERROR',
                    '{getSupportMessage} (#{messageId})',
                    [
                        'messageId' => $this->getLoginFailureMessageId(),
                        'getSupportMessage' => $this->getSupportMessage()
                    ]
                )
            );
        }

        return true;

    }

    /**
     * @inheritdoc
     */
    protected function findOrCreateMember(AccessToken $token, AbstractProvider $provider)
    {

        $session = $this->getSession();

        $user = $provider->getResourceOwner($token);

        $this->applyOktaGroupRestriction($user);

        $identifier = $user->getId();
        $providerName = $session->get('oauth2.provider');

        $userEmail = $user->getEmail();
        if(!$userEmail) {
            $this->setLoginFailureCode(self::FAIL_USER_MISSING_EMAIL, $user->getId());
            throw new ValidationException(
                _t(
                    'OKTA.GENERAL_SESSION_ERROR',
                    '{getSupportMessage} (#{messageId})',
                    [
                        'messageId' => $this->getLoginFailureMessageId(),
                        'getSupportMessage' => $this->getSupportMessage()
                    ]
                )
            );
        }

        if(empty($providerName)) {
            $this->setLoginFailureCode(self::FAIL_NO_PROVIDER_NAME, $user->getId());
            throw new ValidationException(
                _t(
                    'OKTA.GENERAL_SESSION_ERROR',
                    '{getSupportMessage} (#{messageId})',
                    [
                        'messageId' => $this->getLoginFailureMessageId(),
                        'getSupportMessage' => $this->getSupportMessage()
                    ]
                )
            );
        }

        /** @var Passport $passport */
        $passport = $this->getPassport($identifier, $providerName);
        if (!$passport) {

            // Create the new member (or return a matching one if config allows)
            $member = $this->createMember($token, $provider);

            if(!$member) {
                $this->setLoginFailureCode(self::FAIL_NO_PASSPORT_NO_MEMBER_CREATED, $user->getId());
                throw new ValidationException(
                    _t(
                        'OKTA.INVALID_MEMBER',
                        '{getSupportMessage} (#{messageId})',
                        [
                            'messageId' => $this->getLoginFailureMessageId()
                        ]
                    )
                );
            }

            // validate whether a passport already exists for the member/provider
            // this could occur if user B email address claims a member account
            // with the same email address
            $memberPassport = $this->getMemberPassport($member, $providerName);
            if($memberPassport && $memberPassport->exists()) {
                $this->setLoginFailureCode(self::FAIL_USER_MEMBER_PASSPORT_MISMATCH, $user->getId());
                throw new ValidationException(
                    _t(
                        'OKTA.INVALID_MEMBER',
                        '{getSupportMessage} (#{messageId})',
                        [
                            'messageId' => $this->getLoginFailureMessageId()
                        ]
                    )
                );
            }

            // Assign created member to passport
            $passport = $this->createPassport($identifier, $providerName);
            $passport->MemberID = $member->ID;
            $passport->write();

        } else {

            // Passport exists, validate it
            $member = $passport->Member();

            if(!$member) {
                $this->setLoginFailureCode(self::FAIL_PASSPORT_NO_MEMBER_CREATED, $user->getId());
                throw new ValidationException(
                    _t(
                        'OKTA.INVALID_MEMBER',
                        '{getSupportMessage} (#{messageId})',
                        [
                            'messageId' => $this->getLoginFailureMessageId()
                        ]
                    )
                );
            }

            // validate that the Member.Email matches the returned $user email
            // this will be hit if someone's email changes at Okta
            // TODO: sync job via API to pull in updated email address
            if( $member->Email != $userEmail ) {
                $this->setLoginFailureCode(self::FAIL_USER_MEMBER_EMAIL_MISMATCH, $user->getId());
                throw new ValidationException(
                    _t(
                        'OKTA.INVALID_MEMBER',
                        '{getSupportMessage} (#{messageId})',
                        [
                            'messageId' => $this->getLoginFailureMessageId(),
                            'getSupportMessage' => $this->getSupportMessage()
                        ]
                    )
                );
            }

        }

        $this->assignGroups($user, $member);

        return $member;
    }

    /**
     * Given a user returned from Okta, assign their configured groups
     * if the groups were also returned
     * Groups are returned by adding the 'group' scope to the AccessToken claim
     * You must add a "Groups claim filter" = 'groups' 'Matches regex' '.*' in the Service app
     * OpenID Connect ID Token section
     * @see https://developer.okta.com/docs/guides/customize-tokens-groups-claim/add-groups-claim-org-as/
     */
    protected function assignGroups(ResourceOwnerInterface $user, Member $member) {
        // assign groups to the member
        $data = $user->toArray();
        if(!empty($data['groups']) && is_array($data['groups'])) {
            $inst = Group::create();
            $parent = $inst->applyOktaRootGroup();
            if($parent && $parent->isInDB()) {
                foreach($data['groups'] as $groupName) {

                    // if group exists
                    $group = Group::get()->filter([
                        'Title' => $groupName,
                        'IsOktaGroup' => 1
                    ])->first();

                    if(empty($group->ID)) {
                        $group = Group::create();
                        $group->ParentID = $parent->ID;
                        $group->IsOktaGroup = 1;
                        $group->Title = $groupName;
                        $group->write();
                    }
                    // ensure linked to group
                    $member->Groups()->add($group);
                }
            }
        }
    }

    /**
     * Create a member from the given token
     *
     * @param AccessToken $token
     * @param AbstractProvider $provider
     * @return Member
     * @throws ValidationException
     */
    protected function createMember(AccessToken $token, AbstractProvider $provider)
    {

        $session = $this->getSession();
        $providerName = $session->get('oauth2.provider');
        $user = $provider->getResourceOwner($token);
        $userEmail = $user->getEmail();

        // require a user email for this operation
        if(!$userEmail) {
            $this->setLoginFailureCode(self::FAIL_USER_MISSING_EMAIL, $user->getId());
            throw new ValidationException(
                _t(
                    'OKTA.NO_EMAIL_RETURNED',
                    '{getSupportMessage} (#{messageId})',
                    [
                        'messageId' => $this->getLoginFailureMessageId(),
                        'getSupportMessage' => $this->getSupportMessage()
                    ]
                )
            );
        }

        // require a provider name for this operation
        if(empty($providerName)) {
            $this->setLoginFailureCode(self::FAIL_NO_PROVIDER_NAME, $user->getId());
            throw new ValidationException(
                _t(
                    'OKTA.GENERAL_SESSION_ERROR',
                    '{getSupportMessage} (#{messageId})',
                    [
                        'messageId' => $this->getLoginFailureMessageId(),
                        'getSupportMessage' => $this->getSupportMessage()
                    ]
                )
            );
        }

        /* @var Member|null */
        $claimedMember = Member::get()->filter('Email', $userEmail)->first();
        $identifier = $user->getId();

        if(!$claimedMember) {
            // no existing member for the user's email address, can create one
            $member = Member::create();
            $member = $this->getMapper($providerName)->map($member, $user);
            // Retained for compat with LoginTokenHandler
            $member->OAuthSource = null;
            $member->write();
        } else if($this->config()->get('link_existing_member')) {
            // Member exists, update mapped fields from the provider
            // TODO: select a primary provider for fields if multiple providers?
            $member = $this->getMapper($providerName)->map($claimedMember, $user);
            $member->OAuthSource = null;
            $member->write();
        } else {
            // Member exists, but collision detected and config disallows linking
            $this->setLoginFailureCode(self::FAIL_USER_MEMBER_COLLISION, $user->getId());
            throw new ValidationException(
                _t(
                    'OKTA.MEMBER_COLLISION',
                    '{getSupportMessage} (#{messageId})',
                    [
                        'messageId' => $this->getLoginFailureMessageId(),
                        'getSupportMessage' => $this->getSupportMessage()
                    ]
                )
            );
        }
        return $member;
    }
}
