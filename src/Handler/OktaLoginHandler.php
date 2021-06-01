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
     * Given an identifier and a provider string, return the Passport matching
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
            throw new ValidationException(
                _t(
                    'OKTA.GENERAL_SESSION_ERROR',
                    'Sorry, we could not sign you in. Please try again.'
                )
            );
        }

        if(empty($providerName)) {
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
            // Create a passport
            $passport = $this->createPassport($identifier, $providerName);
            // Create the new member (or return a matching one if config allows)
            $member = $this->createMember($token, $provider);
            if(!$member) {
                throw new ValidationException(
                    _t(
                        'OKTA.INVALID_MEMBER',
                        'Sorry, there was an issue finding your account. Please try again or contact support'
                    )
                );
            }
            $passport->MemberID = $member->ID;
            $passport->write();
        } else {

            // Passport exists, validate it
            $member = $passport->Member();

            if(!$member) {
                throw new ValidationException(
                    _t(
                        'OKTA.INVALID_MEMBER',
                        'Sorry, there was an issue finding your account. Please try again or contact support'
                    )
                );
            }

            // validate that the Member.Email matches the returned $user email
            // this will be hit if someone's email changes at Okta
            // TODO: sync job via API to pull in update email address
            if( $member->Email != $userEmail ) {
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
        if(!$userEmail) {
            throw new ValidationException(
                _t(
                    'OKTA.NO_EMAIL_RETURNED',
                    'Okta did not provide your email address'
                )
            );
        }

        /* @var Member|null */
        $member = Member::get()->filter('Email', $userEmail)->first();
        if(!$member) {
            // no existing member, can create one
            $member = Member::create();
            $member = $this->getMapper($providerName)->map($member, $user);
            // Retained for compat with LoginTokenHandler
            $member->OAuthSource = null;
            $member->write();
        } else if($this->config()->get('link_existing_member')) {
            // Member exists, update mapped fields
            $member = $this->getMapper($providerName)->map($member, $user);
            $member->OAuthSource = null;
            $member->write();
        } else {
            // Member exists, but collision detected
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
