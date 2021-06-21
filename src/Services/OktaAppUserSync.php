<?php

namespace NSWDPC\Authentication\Okta;

use Bigfork\SilverStripeOAuth\Client\Model\Passport;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Convert;
use SilverStripe\ORM\ArrayList;
use SilverStripe\Security\Group;
use SilverStripe\Security\Member;
use SilverStripe\Security\Permission;

/**
 * Synchronises the users assigned with the application
 */
class OktaAppUserSync
{
    use OktaGroups;

    /**
     * A user assigned to an application directly
     */
    const APPUSER_SCOPE_USER = 'USER';

    /**
     * A user assigned to an application via a group
     */
    const APPUSER_SCOPE_GROUP = 'GROUP';

    /**
     * @var \Okta\Client|null
     */
    private $client = null;


    /**
     * @var bool
     */
    private $dryRun = false;

    /**
     * @var string
     */
    private $start = '';

    /**
     * @var array
     */
    private $report = [];

    /**
     * @var HttpClient
     */
    protected $httpClient = null;

    /**
     * Get the configured {@link \Okta\Client}, if not available create it from configuration
     */
    protected function getClient($parameters = []) : \Okta\Client
    {
        if (!$this->client) {
            $this->httpClient = new ProxiedCurlHttpClient();
            $this->client = ClientFactory::create($parameters, $this->httpClient);
        }
        return $this->client;
    }

    /**
     * Client ID for the application being synchronised
     */
    protected function getClientId() : string
    {
        return Config::inst()->get(ClientFactory::class, 'application_client_id');
    }

    /**
     * Return the sync report, which is an array, keys are Okta User Ids, each value is an array
     * of changes performed on that user
     * Report is only gathered in dryRun mode
     * @return array
     */
    public function getReport() : array
    {
        return $this->report;
    }

    /**
     * Return the users successfully sync as an array, keys are Okta user ids, values is the match Member.ID
     * @return array
     */
    public function getSuccesses() : array
    {
        return $this->success;
    }

    /**
     * Return the failed sync attempts, array of okta user id values
     * @return array
     */
    public function getFailures() : array
    {
        return $this->fail;
    }

    /**
     * Run the sync processing
     * @see https://developer.okta.com/docs/reference/api/apps/#list-users-assigned-to-application
     * @param bool $dryRun when true, no changes are made to local members. A report is created and can be accessed via getReport()
     * @param int $limit the number of records to return per page, if 0 the default Okta value is used (50 based on docs)
     * @throws \Exception
     */
    public function run(bool $dryRun = false, int $limit = 50) : int
    {
        $this->success = $this->fail = [];
        $this->dryRun = $dryRun;
        if ($this->dryRun) {
            Logger::log("OktaApplicationSynchroniser::run in dryRun mode", "DEBUG");
        }

        // create/configure the Okta client
        $client = $this->getClient();

        $this->getAppUsers($limit);

        $dt = new \DateTime();
        $this->start = $dt->format('Y-m-d H:i:s');
        $successCount = $this->processAppUsers($this->appUsers);
        $failCount = count($this->fail);
        Logger::log("OKTA: processUsers complete, {$successCount} users successfully synced, {$failCount} fails", "INFO");
        return $successCount;
    }

    /**
     * Collect all app users via pagination method
     * @param
     * @return void
     */
    private function getAppUsers(int $limit = 50)
    {

        // Initial set
        $this->appUsers = new \Okta\Applications\Collection([]);

        // initial properties for App users request
        $properties = new \stdClass;
        $properties->id = $this->getClientId();
        if (empty($properties->id)) {
            throw new \Exception("No App ClientId configured (ClientFactory.application_client_id)");
        }
        $resource = new \Okta\Applications\Application(null, $properties);

        // initial options for initial request
        $options = [
            'query' => [
                'limit' => $limit
            ]
        ];
        $this->collectAppUsers($options, $resource);
    }

    /**
     * Get all appusers based on configuration
     * @param array $options
     * @param Okta\Applications\Application $resource
     */
    private function collectAppUsers(array $options, \Okta\Applications\Application $resource)
    {
        // @var \Okta\Applications\Collection
        $collection = $resource->getApplicationUsers($options);
        if ($collection instanceof \Okta\Applications\Collection) {
            // merge the returned collection on
            if (!$this->appUsers) {
                $this->appUsers = $collection;
            } else {
                $this->appUsers = $this->appUsers->merge($collection);
            }
            try {
                $options = $this->httpClient->getNextPageOptions();
                // get the next set
                $this->collectAppUsers(['query' => $options ], $resource);
            } catch (\Exception $e) {
                // getNextPageOptions threw an exception (or no more results)
            }
        }
        return false;
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
     * Collect all groups for a user
     * @param array $options
     * @param \Okta\Users\User $resource
     * @param \Okta\Groups\Collection $userGroups
     */
    private function collectUserGroups(array $options, \Okta\Users\User $resource, \Okta\Groups\Collection &$userGroups)
    {
        // @var \Okta\Groups\Collection
        if (!$resource->getId()) {
            throw new \Exception("To get user groups, the user resource must have an Id");
        }
        $collection = $resource->getGroups($options);
        if ($collection instanceof \Okta\Groups\Collection) {
            // merge the returned collection on
            $userGroups = $userGroups->merge($collection);
            try {
                $options = $this->httpClient->getNextPageOptions();
                // get the next set
                $this->collectUserGroups(['query' => $options ], $resource, $userGroups);
            } catch (\Exception $e) {
                // getNextPageOptions threw an exception (or no more results)
            }
        }
        return false;
    }

    /**
     * Process a single app user return in the collection
     * AppUser profile vs User profile
     * https://help.okta.com/en/prod/Content/Topics/users-groups-profiles/usgp-about-profiles.htm
     * @param \Okta\Applications\AppUser $appUser
     * @throws OktaAppUserSyncException
     */
    protected function processAppUser(\Okta\Applications\AppUser $appUser) : Member
    {
        $userId = $appUser->getId();

        // Get the corresponding user record
        $userResource = new \Okta\Users\User();
        $user = $userResource->get($userId);

        // initial request options
        $options = [
            'query' => [
                'limit' => 50
            ]
        ];
        // initially no groups
        $userGroups = new \Okta\Groups\Collection([]);
        $this->collectUserGroups($options, $user, $userGroups);

        // @var \Okta\Users\UserProfile
        $userProfile = $user->getProfile();
        if (!($userProfile instanceof \Okta\Users\UserProfile)) {
            throw new OktaAppUserSyncException("AppUser {$userId} has no Okta user profile");
        }

        // @var string - either USER or GROUP
        $appUserScope = $appUser->getScope();
        Logger::log("AppUser.id={$userId} User.id={$user->getId()} scope={$appUserScope}", "DEBUG");

        // @var string
        $userUsername = $userProfile->getLogin();
        if (!$userUsername) {
            throw new OktaAppUserSyncException("AppUser {$userId} profile has no username value");
        }

        $passport = Passport::get()->filter([
            'Identifier' => $userId,
            'OAuthSource' => 'Okta' // @todo constant
        ])->first();

        if (!$passport) {
            throw new OktaAppUserSyncException("AppUser {$userId} has no Okta passport - not signed in yet?");
        }

        // Retrieve member based on matching username
        $member = Member::get()->filter('Email', $userUsername)->first();
        if (!$member) {
            throw new OktaAppUserSyncException("AppUser {$userId} has no matching Member record using {$userUsername}");
        }

        if ($passport->MemberID != $member->ID) {
            throw new OktaAppUserSyncException("AppUser {$userId} Passport.MemberID #{$passport->MemberID}/Member #{$member->ID} - passport found mismatch with member found");
        }

        // Allowed map fields, @todo use MemberMapper similar to OAuth
        // at this point we just retrieve name from Okta and save that to keep in sync
        $mapping = [
            'FirstName' => $this->sanitiseProfileValue($userProfile->getFirstName()),
            'Surname' => $this->sanitiseProfileValue($userProfile->getLastName())
        ];

        // Apply profile fields to the Member record
        foreach ($mapping as $memberField => $fieldValue) {
            Logger::log("AppUser.id={$userId} mapping {$memberField} to {$fieldValue}", "DEBUG");

            if (empty($fieldValue)) {
                continue;
            }

            if ($this->dryRun) {
                $this->report[$userId][] = "Member {$member->ID} set field {$memberField} to Okta value {$fieldValue}";
            } else {
                $member->{$memberField} = $fieldValue;
            }
        }

        if ($this->dryRun) {
            $this->report[$userId][] = "Would write profile for Member #{$member->ID}";
        //$this->report[$userId][] = print_r($userProfile, true);
        } else {
            $member->OktaProfile = $userProfile->__toString();
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
     * Ensure that a profile has HTML removed
     */
    private function sanitiseProfileValue($value) : string
    {
        if (is_scalar($value)) {
            return trim(strip_tags($value));
        } else {
            return '';
        }
    }

    /**
     * Returns a list of stale members, which could be empty!
     * Members with a CMS_ACCESS permission are not returned
     * @return \SilverStripe\ORM\ArrayList
     */
    public function getStaleOktaMembers() : ArrayList
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
                    );
        foreach ($members as $member) {
            if (!Permission::checkMember($member, 'CMS_ACCESS')) {
                $membersToRemove->push($member);
            }
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
