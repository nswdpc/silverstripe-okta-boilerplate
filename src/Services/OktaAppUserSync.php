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
     * @param bool $dryRun when true, no changes are made to local members. A report is created and can be accessed via getReport()
     * @param int $limit the number of records to return per page, if 0 the default Okta value is used (50 based on docs)
     * @param array $queryOptions extra filtering options to pass to the Okta API
     * @throws \Exception
     */
    public function run(bool $dryRun = false, int $limit = 50, array $queryOptions = []) : int
    {
        $this->success = $this->fail = [];
        $this->dryRun = $dryRun;
        if ($this->dryRun) {
            Logger::log("OktaApplicationSynchroniser::run in dryRun mode", "DEBUG");
        }

        $this->getAppUsers($limit, $queryOptions);

        $dt = new \DateTime();
        $this->start = $dt->format('Y-m-d H:i:s');
        $successCount = $this->processAppUsers($this->appUsers);
        $failCount = count($this->fail);
        Logger::log("OKTA: processUsers complete, {$successCount} users successfully synced, {$failCount} fails", "INFO");
        return $successCount;
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
            $member->OktaProfile->setValue( $userProfile->__toString() );
            $member->OktaLastSync = $this->start;
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

    /**
     * Returns a list of stale members, which could be empty!
     * Members with a CMS_ACCESS permission are not returned
     * @return \SilverStripe\ORM\ArrayList
     */
    public function getStaleOktaMembers(int $limit = 0) : ArrayList
    {
        $membersToRemove = ArrayList::create();
        $days = intval(Config::inst()->get(Member::class, 'okta_lockout_after_days'));
        if ($days <= 0) {
            return $membersToRemove;
        }
        $threshold = new \DateTime();
        $threshold->modify("-{$days} day");
        $datetime = $threshold->format('Y-m-d') . 'T00:00:00';
        $members = Member::get()
                    ->where(
                        "OktaLastSync <> ''"
                        . " AND OktaLastSync IS NOT NULL"
                        . " AND OktaLastSync < '" . Convert::raw2sql($datetime) . "'"
                    )->sort('OktaLastSync ASC');
        foreach ($members as $member) {
            if (!Permission::checkMember($member, 'CMS_ACCESS')) {
                $membersToRemove->push($member);
            }
        }
        if($limit > 0) {
            $membersToRemove = $membersToRemove->limit($limit);
        }
        return $membersToRemove;
    }

    /**
     * Remove any member that is consider a stale Okta user
     * @param bool $dryRun when true, only return the user count delete total, don't actually delete Member records
     * @return int
     */
    public function removeStaleOktaMembers($dryRun = false) : int
    {
        $list = $this->getStaleOktaMembers();
        $deleted = 0;
        foreach ($list as $member) {
            // remove member and passports (at the least)
            if (!$dryRun) {
                $member->delete();
            }
            $deleted++;
        }
        return $deleted;
    }

}
