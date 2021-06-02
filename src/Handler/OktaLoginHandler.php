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

    /**
     * @inheritdoc
     */
    public function handleToken(AccessToken $token, AbstractProvider $provider)
    {
        $this->setLoginFailureCode(null);//reset failure code on new attempt
        return parent::handleToken($token, $provider);
    }

    /**
     * @param string|null $code
     */
    protected function setLoginFailureCode($code) {
        $this->loginFailureCode = $code;
    }

    /**
     * @return string|null
     */
    public function getLoginFailureCode() {
        return $this->loginFailureCode;
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
            $this->setLoginFailureCode(self::FAIL_USER_NO_GROUPS);
            throw new ValidationException(
                _t(
                    'OKTA.GENERAL_SESSION_ERROR',
                    'Sorry, we could not sign you in. You do not have access to this website, please contact support.'
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
            $this->setLoginFailureCode(self::FAIL_USER_MISSING_REQUIRED_GROUPS);
            throw new ValidationException(
                _t(
                    'OKTA.GENERAL_SESSION_ERROR',
                    'Sorry, we could not sign you in. You do not have access to this website, please contact support.'
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
            $this->setLoginFailureCode(self::FAIL_USER_MISSING_EMAIL);
            throw new ValidationException(
                _t(
                    'OKTA.GENERAL_SESSION_ERROR',
                    'Sorry, we could not sign you in. Please try again.'
                )
            );
        }

        if(empty($providerName)) {
            $this->setLoginFailureCode(self::FAIL_NO_PROVIDER_NAME);
            throw new ValidationException(
                _t(
                    'OKTA.GENERAL_SESSION_ERROR',
                    'Sorry, we could not sign you in. Please try again.'
                )
            );
        }

        /** @var Passport $passport */
        $passport = $this->getPassport($identifier, $providerName);
        if (!$passport) {

            // Create the new member (or return a matching one if config allows)
            $member = $this->createMember($token, $provider);

            if(!$member) {
                $this->setLoginFailureCode(self::FAIL_NO_PASSPORT_NO_MEMBER_CREATED);
                throw new ValidationException(
                    _t(
                        'OKTA.INVALID_MEMBER',
                        'Sorry, there was an issue finding your account. Please try again or contact support'
                    )
                );
            }

            // validate whether a passport already exists for the member/provider
            // this could occur if user B email address claims a member account
            // with the same email address
            $memberPassport = $this->getMemberPassport($member, $providerName);
            if($memberPassport && $memberPassport->exists()) {
                $this->setLoginFailureCode(self::FAIL_USER_MEMBER_PASSPORT_MISMATCH);
                throw new ValidationException(
                    _t(
                        'OKTA.INVALID_MEMBER',
                        'Sorry, there was an issue finding your account. Please try again or contact support'
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
                $this->setLoginFailureCode(self::FAIL_PASSPORT_NO_MEMBER_CREATED);
                throw new ValidationException(
                    _t(
                        'OKTA.INVALID_MEMBER',
                        'Sorry, there was an issue finding your account. Please try again or contact support'
                    )
                );
            }

            // validate that the Member.Email matches the returned $user email
            // this will be hit if someone's email changes at Okta
            // TODO: sync job via API to pull in updated email address
            if( $member->Email != $userEmail ) {
                $this->setLoginFailureCode(self::FAIL_USER_MEMBER_EMAIL_MISMATCH);
                throw new ValidationException(
                    _t(
                        'OKTA.INVALID_MEMBER',
                        'Sorry, there was an issue finding your account. Please try again or contact support'
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
            $this->setLoginFailureCode(self::FAIL_USER_MISSING_EMAIL);
            throw new ValidationException(
                _t(
                    'OKTA.NO_EMAIL_RETURNED',
                    'Okta did not provide your email address'
                )
            );
        }

        // require a provider name for this operation
        if(empty($providerName)) {
            $this->setLoginFailureCode(self::FAIL_NO_PROVIDER_NAME);
            throw new ValidationException(
                _t(
                    'OKTA.GENERAL_SESSION_ERROR',
                    'Sorry, we could not sign you in. Please try again.'
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
            $this->setLoginFailureCode(self::FAIL_USER_MEMBER_COLLISION);
            throw new ValidationException(
                _t(
                    'OKTA.MEMBER_COLLISION',
                    'Sorry, we could not sign you in. Please contact support to assist'
                )
            );
        }
        return $member;
    }
}
