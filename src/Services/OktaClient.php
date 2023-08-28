<?php

namespace NSWDPC\Authentication\Okta;

use SilverStripe\Core\Config\Configurable;
use SilverStripe\ORM\DataList;
use SilverStripe\Security\Member;

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
     * @var \DateTime
     */
    protected $start = null;

    /**
     * @var ProxiedCurlHttpClient
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
     * @var bool
     * When true, a single page of results is returned
     */
    protected $singlePage = true;

    /**
     * Store the 'after' value when a page of results is returned
     * @var string|null
     */
    protected $cursorAfter = null;


    /**
     * Error code for resource not found
     * @var string
     */
    const RESOURCE_NOT_FOUND = "E0000007";

    /**
     * Set up Okta client and parameters
     */
    public function __construct($isDryRun = false) {
        $this->start = new \DateTime();
        $this->setIsDryRun($isDryRun);
        $this->getClient();
    }

    /**
     * Trigger whether operations make changes or report-only
     */
    public function setIsDryRun(bool $is) : self {
        $this->dryRun = $is;
        return $this;
    }

    /**
     * Store whether the request should proceed to the next page of results (false) or not (true)
     * @param bool $is
     */
    public function setIsSinglePage(bool $is) : self {
        $this->singlePage = $is;
        return $this;
    }

    /**
     * Return the after cursor value
     */
    public function getCursorAfter() : ?string {
        return $this->cursorAfter;
    }

    /**
     * Get the configured {@link \Okta\Client}, if not available create it from configuration
     */
    protected function getClient($parameters = []) : \Okta\Client
    {
        if (!$this->client) {
            $this->httpClient = new ProxiedCurlHttpClient();
            /**
             * Use the VoidCacheManager
             */
            $cacheManager = new VoidCacheManager();
            $this->client = ClientFactory::create($parameters, $this->httpClient, $cacheManager);
        }
        return $this->client;
    }

    /**
     * Format the operation start \DateTime into a string
     * @return string
     */
    protected function startFormatted(string $format = "Y-m-d H:i:s") : string {
        return $this->start->format($format);
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
     * Return members with an OktaLoginProfile value
     */
    final protected function getLinkedMembers() : DataList {
        return Member::get()->exclude([ "OktaProfileLogin" => ["",null] ]);
    }

    /**
     * Return members with an OktaLoginProfile value who have a OktaLastSync datetime
     */
    final protected function getSyncedMembers() : DataList {
        $members = $this->getLinkedMembers();
        $members = $members->exclude([ "OktaLastSync" => ["",null] ]);
        $members = $members->sort('OktaLastSync ASC');
        return $members;
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
     * @param string $identifier
     */
    final public function getUser(string $identifier) : ?\Okta\Users\User {
        $resource = $this->getUserResource();
        $user = $resource->get($identifier);
        return $user;
    }

    /**
     * Get an Okta user profile, from an Okta user record
     * @param \Okta\Users\User $user Okta user record
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
