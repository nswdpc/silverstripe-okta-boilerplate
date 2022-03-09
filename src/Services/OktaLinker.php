<?php

namespace NSWDPC\Authentication\Okta;

use Foxworth42\OAuth2\Client\Provider\OktaUser;
use Okta\Users\UserProfile;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Security\Member;

/**
 * Service class to link an Okta user via login or sync to a Silverstripe Member
 */
class OktaLinker {

    use Configurable;

    /**
     * @var bool
     * If true, link to an existing member based on Email/Okta username
     * Note: this assumes that the owner of the Okta username is the owner of
     * the Silverstripe Member.Email address
     * If you cannot ensure that, set this value in your project configuration to false
     */
    private static $update_existing_member = true;

    /**
     * @var bool
     * If true, and login matching fails, allow Member linking where the
     * Okta login value for the member equals the Member.Email
     */
    private static $link_via_email = false;

    /**
     * Link via an OAuth sign-in, via the OktaUser resource
     * @param OktaUser $user resource from OAuth signin
     */
    public static function linkViaOktaUser(OktaUser $user, $createIfNotExisting = true) : ?Member {
        return self::linktoMember(
            $createIfNotExisting,
            $user->getPreferredUsername(),
            $user->getEmail(),
            $user->getFirstName(),
            $user->getLastName()
        );
    }

    /**
     * Link via a UserProfile returned from the Okta API
     * @param UserProfile $userProfile resource
     */
    public static function linkViaUserProfile(UserProfile $userProfile, $createIfNotExisting = false) : ?Member {
        return self::linktoMember(
            $createIfNotExisting,
            $userProfile->getLogin(),
            $userProfile->getEmail(),
            $userProfile->getFirstName(),
            $userProfile->getLastName()
        );
    }

    /**
     * This is the default behaviour
     * Find a Member via Okta login <-> Member.Email
     */
    protected static function linkLoginEmail(string $userLogin) : ?Member {
        return Member::get()->filter('Email', $userLogin)->first();
    }

    /**
     * This is the default behaviour
     * Find a Member via Okta login <-> Member.Email
     */
    protected static function linkLoginLogin(string $userLogin) : ?Member {
        return Member::get()->filter('OktaProfileLogin', $userLogin)->first();
    }

    /**
     * Based on the configured linking method, find or create a member record
     * @note newly created Member records are not written, to allow reporting
     * @param bool $createIfNotExisting create a Member record if one does not exist
     * @param string $userLogin an Okta user login
     * @param string $userEmail an Okta primary email address
     * @param string $userFirstName an Okta user given_name or firstname
     * @param string $userSurname an Okta user family_name or surname
     * @return Member|null
     */
    protected static function linktoMember(bool $createIfNotExisting = true, string $userLogin, string $userEmail, string $userFirstName = '', string $userSurname = '') : ?Member {

        // Linking requires both the Okta login and email values
        if(!$userLogin || !$userEmail) {
            return null;
        }

        // Attempt to find Member via Member.OktaProfileLogin
        $member = self::linkLoginLogin($userLogin);
        if($member) {
            Logger::log("OktaLinker: found via linkLoginLogin login={$userLogin} email={$userEmail}", "DEBUG");
        } else if(!$member && self::config()->get('link_via_email')) {
            Logger::log("OktaLinker: link_via_email=on", "DEBUG");
            // Attempt to find Member via Member.Email
            $member = self::linkLoginEmail($userLogin);
        }

        if (!$member && $createIfNotExisting) {
            // Create a new Member if allowed
            Logger::log("OktaLinker: create new member login={$userLogin} email={$userEmail}", "DEBUG");
            $member = Member::create();
            $member->FirstName = $userFirstName;
            $member->Surname = $userSurname;
            $member->Email = $userEmail;
            $member->OktaProfileLogin = $userLogin;
            // Retained for compat with LoginTokenHandler
            $member->OAuthSource = null;
        } else if ($member && self::config()->get('update_existing_member')) {
            // Member exists, update base fields from the provider
            Logger::log("OktaLinker: link current member login={$userLogin} email={$userEmail}", "DEBUG");
            $member->FirstName = $userFirstName;
            $member->Surname = $userSurname;
            $member->OAuthSource = null;
            if(!$member->OktaProfileLogin) {
                $member->OktaProfileLogin = $userLogin;
            }
        }
        Logger::log("OktaLinker: returning a " . ($member ? 'member' : 'null'), "DEBUG");
        return $member;
    }

 }
