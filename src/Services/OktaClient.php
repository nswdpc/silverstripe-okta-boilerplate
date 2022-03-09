<?php

namespace NSWDPC\Authentication\Okta;

use SilverStripe\Core\Config\Configurable;

/**
 * Class providing common methods for accessing Okta resources
 * @author James
 */
abstract class OktaClient
{

    use OktaGroups;

    use Configurable;

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
     * Create the Okta client immediately
     */
    public function __construct() {
        $this->getClient();
    }

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
     * Return the resource used to access Okta User operations
     * @param object $properties passed during resource creation
     */
    final protected function getUserResource(object $properties = null) : \Okta\Users\User {
        if(!$properties) {
            $properties = new \stdClass;
        }
        $resource = new \Okta\Users\User(null, $properties);
        return $resource;
    }

    /**
     * Get an Okta user, based on the provided identifier
     * @see https://developer.okta.com/docs/reference/api/users/#get-user
     * @param string
     */
    final public function getUser(string $identifier) : ?\Okta\Users\User {
        $resource = $this->getUserResource();
        $user = $resource->get($identifier);
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
            throw new OktaClientException("AppUser {$user->getId()} has no Okta user profile");
        }
        return $userProfile;
    }

    /**
     * Collect all groups for a user
     * @param array $options
     * @param \Okta\Users\User $user
     * @param \Okta\Groups\Collection $userGroups
     */
    final protected function collectUserGroups(array $options, \Okta\Users\User $user, \Okta\Groups\Collection &$userGroups)
    {
        // @var \Okta\Groups\Collection
        if (!$user->getId()) {
            throw new \Exception("To get user groups, the user resource must have an Id");
        }
        $collection = $user->getGroups($options);
        if ($collection instanceof \Okta\Groups\Collection) {
            // merge the returned collection on
            $userGroups = $userGroups->merge($collection);
            try {
                $options = $this->httpClient->getNextPageOptions();
                // get the next set
                $this->collectUserGroups(['query' => $options ], $user, $userGroups);
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
