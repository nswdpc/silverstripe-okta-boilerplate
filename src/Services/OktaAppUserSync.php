<?php

namespace NSWDPC\Authentication\Okta;

use Bigfork\SilverStripeOAuth\Client\Model\Passport;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Convert;
use SilverStripe\ORM\ArrayList;
use SilverStripe\Security\Group;
use SilverStripe\Security\Member;
use SilverStripe\Security\Permission;

/**
 * Synchronises the users assigned to the application with the local Member records
 */
class OktaAppUserSync extends OktaAppClient
{

    /**
     * @var bool
     * When true, Member records will be created from sync data
     * When false, only those members who have signed in will be created
     */
    private static $create_users = true;

    /**
     * Run the sync processing
     * @see https://developer.okta.com/docs/reference/api/apps/#list-users-assigned-to-application
     * @param array $queryOptions extra filtering options to pass to the Okta API, including limit
     * @throws \Exception
     */
    public function run(array $queryOptions = []) : int
    {
        $this->success = $this->fail = [];

        if ($this->dryRun) {
            Logger::log("OktaApplicationSynchroniser::run in dryRun mode", "DEBUG");
        }

        $this->getAppUsers($queryOptions);

        $this->start = new \DateTime();
        $successCount = $this->processAppUsers($this->appUsers);
        $failCount = count($this->fail);
        Logger::log("OKTA: processUsers complete, {$successCount} users successfully synced, {$failCount} fails", "INFO");
        $unlinkedMembers = $this->handleUnlinkedMembers();
        Logger::log("OKTA: processUsers {$unlinkedMembers} unlinked member(s) found", "INFO");
        return $successCount;
    }

    /**
     * Remove Okta values from members no longer linked to the configured application
     * Based on the value of their last sync date in this operation
     * @return int the number of Members no longer found in the configured application
     */
    protected function handleUnlinkedMembers() : int {
        if($members = $this->getUnlinkedMembers($this->start)) {
            foreach($members as $member) {
                if(!$this->dryRun) {
                    $passports = $member->Passports()->filter(['OAuthSource' => 'Okta']);
                    foreach($passports as $passport) {
                        $passport->delete();
                    }
                    // Members without permissions are removed
                    $permissions = Permission::permissions_for_member($member);
                    if (empty($permissions)) {
                        Logger::log("OKTA: handleUnlinkedMembers removing unlinked member #{$member->ID}", "NOTICE");
                        $member->delete();
                    } else {
                        // Unlinked Okta values
                        Logger::log("OKTA: handleUnlinkedMembers removing okta values from member #{$member->ID}", "INFO");
                        $member->OktaLastSync = '';
                        $member->OktaUnlinkedWhen = $this->startFormatted();
                        $member->OktaProfileValue = '';
                        $member->write();
                    }
                } else {
                    $this->report["Member #{$member->ID}"][] = "Not linked to application";
                }
            }
            return $members->count();
        } else {
            return 0;
        }
    }

    /**
     * Process the collection of application users
     * @param \Okta\Applications\Collection $appUsers all the users in the application
     */
    protected function processAppUsers(\Okta\Applications\Collection $appUsers) : int
    {
        Logger::log("OKTA: Processing appUser collection count=" . count($appUsers), "INFO");
        foreach ($appUsers as $appUser) {
            try {
                $userId = $appUser->getId();
                /**
                 * Process a single AppUser, the return value is the matched/updated member
                 * When no member is found or an error occurs, an Exception is thrown
                 * Processing continues to the next app user returned
                 */
                $member = $this->processAppUser($appUser);
                Logger::log("OKTA: Processing appUser completed, got Member #{$member->ID}", "INFO");
                $this->success[ $userId ] = $member->ID;
            } catch (OktaAppUserSyncException $e) {
                Logger::log("Okta: appuser sync error in processUsers error=" . $e->getMessage(), "NOTICE");
                $this->fail[] = $userId;
            } catch (\Exception $e) {
                Logger::log("Okta: general error in processUsers error=" . $e->getMessage(), "NOTICE");
                $this->fail[] = $userId;
            }
        }
        return count($this->success);
    }

    /**
     * Process a single app user return in the collection
     * AppUser profile vs User profile: https://help.okta.com/en/prod/Content/Topics/users-groups-profiles/usgp-about-profiles.htm
     * @param \Okta\Applications\AppUser $appUser
     * @throws OktaAppUserSyncException
     */
    protected function processAppUser(\Okta\Applications\AppUser $appUser) : Member
    {

        // Get the user record, via Okta App userId
        // https://developer.okta.com/docs/reference/api/apps/#application-user-properties
        $user = $this->getUser($appUser->getId());
        $userId = $user->getId();

        // Collect user groups
        // initial request options
        $options = [
            'query' => [
                'limit' => 50
            ]
        ];
        // initially no groups
        $userGroups = new \Okta\Groups\Collection([]);
        $this->collectUserGroups($options, $user, $userGroups);

        // User profile information
        $userProfile = $this->getUserProfile($user);

        // @var string - either USER or GROUP
        $appUserScope = $appUser->getScope();
        Logger::log("AppUser.id={$appUser->getId()} User.id={$user->getId()} scope={$appUserScope}", "DEBUG");

        // @var string
        $userLogin = $userProfile->getLogin();
        if (!$userLogin) {
            throw new OktaAppUserSyncException("AppUser {$userId} profile has no username value");
        }

        // @var string
        $userEmail = $userProfile->getEmail();
        if (!$userLogin) {
            throw new OktaAppUserSyncException("AppUser {$userId} profile has no email value");
        }

        $oktaLinker = new OktaLinker();

        $createUser = $this->config()->get('create_users');
        if(!$createUser) {

            Logger::log("AppUser create users off - passport check", "DEBUG");

            $passport = Passport::get()->filter([
                'Identifier' => $userId,
                'OAuthSource' => 'Okta' // @todo constant
            ])->first();

            if (!$passport) {
                throw new OktaAppUserSyncException("AppUser {$userId} has no Okta passport - not signed in yet?");
            }

            // find a new member, do not create a new one if none found
            $member = $oktaLinker->linkViaUserProfile($userProfile, false);
            if (!$member) {
                throw new OktaAppUserSyncException("AppUser {$userId} has no matching Member record using login={$userLogin},email={$userEmail}");
            }

            if ($member->isInDB() && ($passport->MemberID != $member->ID)) {
                throw new OktaAppUserSyncException("AppUser {$userId} Passport.MemberID #{$passport->MemberID}/Member #{$member->ID} - passport found mismatch with member found");
            }

        } else {
            Logger::log("AppUser create users on - bypass passport check", "DEBUG");
            $member = $oktaLinker->linkViaUserProfile($userProfile, true);
            if (!$member) {
                throw new OktaAppUserSyncException("AppUser {$userId} could not link/create member from profile login={$userLogin},email={$userEmail}");
            }
        }

        if ($this->dryRun) {
            $this->report[$userId][] = "Would write profile for Member #{$member->ID}";
        } else {
            $member->OktaProfileValue = $userProfile;
            $member->OktaLastSync = $this->startFormatted();
            $member->OktaUnlinkedWhen = null;// remove any previous value, if the user was unlinked
            $member->write();
        }

        $groups = [];
        if ($userGroups instanceof \Okta\Groups\Collection) {

            // The group profile contains the group name
            foreach ($userGroups as $userGroup) {
                $groupProfile = $userGroup->getProfile();
                $groups[ $userGroup->getId() ] = $groupProfile->getName();
            }

            if ($this->dryRun) {
                foreach ($groups as $groupId => $groupName) {
                    $this->report[$userId][] = "AppUser.id={$userId} Member #{$member->ID} returned Okta group '{$groupName}'";
                }
            } else {
                // @var array
                $createdOrUpdatedGroups = $this->oktaUserMemberGroupAssignment($groups, $member);
                foreach ($createdOrUpdatedGroups as $createdOrUpdatedGroup) {
                    Logger::log("AppUser.id={$userId} Member {$member->ID} is assigned local Okta group {$createdOrUpdatedGroup}", "DEBUG");
                }
            }
        }

        return $member;
    }

}
