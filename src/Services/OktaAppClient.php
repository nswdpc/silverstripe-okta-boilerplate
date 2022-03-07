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
 * Class providing common methods for Okta search, sync etc
 */
abstract class OktaAppClient
{

    use OktaGroups;

    use Configurable;

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
    protected $client = null;

    /**
     * @var array
     */
    protected $report = [];

    /**
     * @var array
     */
    protected $success = [];

    /**
     * @var array
     */
    protected $fail = [];

    /**
     * @var bool
     */
    protected $dryRun = false;

    /**
     * @var string
     */
    protected $start = '';

    /**
     * @var HttpClient
     */
    protected $httpClient = null;

    /**
     * @var array
     */
    protected $results = [];

    /**
     * @var int
     */
    protected $defaultLimit = 50;

    /**
     * @var \Okta\Applications\Collection
     */
    protected $appUsers;

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
     * Collect all app users via pagination method
     * @param int $limit
     * @param array $queryOptions other filtering options (https://developer.okta.com/docs/reference/api/users/#list-users-with-a-filter)
     * @return void
     */
    final protected function getAppUsers(int $limit = 50, array $queryOptions = [])
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
        $options = ['query' => []];
        if($limit > 0) {
            $options = [
                'query' => [
                    'limit' => $limit
                ]
            ];
        }
        // merge in other options
        $options['query'] = array_merge($options['query'], $queryOptions);
        $this->collectAppUsers($options, $resource);
    }

    /**
     * Get an Okta User, from an application user record
     * @param \Okta\Applications\AppUser Okta App user record, returned from application users list. See: https://developer.okta.com/docs/reference/api/apps/#list-users-assigned-to-application
     */
    final public function getUser(\Okta\Applications\AppUser $appUser) : \Okta\Users\User {
        $userId = $appUser->getId();
        // Get the corresponding user record
        $userResource = new \Okta\Users\User();
        // Retrieve use from API
        $user = $userResource->get($userId);
        return $user;
    }

    /**
     * Get an Okta user profile, from an Okta user record
     * @param \Okta\Users\User Okta user record
     */
    final public function getUserProfile(\Okta\Users\User $user) : \Okta\Users\UserProfile {
        // @var \Okta\Users\UserProfile
        $userProfile = $user->getProfile();
        if (!($userProfile instanceof \Okta\Users\UserProfile)) {
            throw new OktaAppUserSyncException("AppUser {$user->getId()} has no Okta user profile");
        }
        return $userProfile;
    }

    /**
     * Get all appusers based on configuration
     * @param array $options
     * @param Okta\Applications\Application $resource
     */
    final protected function collectAppUsers(array $options, \Okta\Applications\Application $resource)
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
     * Collect all groups for a user
     * @param array $options
     * @param \Okta\Users\User $resource
     * @param \Okta\Groups\Collection $userGroups
     */
    final protected function collectUserGroups(array $options, \Okta\Users\User $resource, \Okta\Groups\Collection &$userGroups)
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
     * Ensure that a profile has HTML removed
     */
    protected function sanitiseProfileValue($value) : string
    {
        if (is_scalar($value)) {
            return trim(strip_tags($value));
        } else {
            return '';
        }
    }
}
