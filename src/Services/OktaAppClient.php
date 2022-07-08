<?php

namespace NSWDPC\Authentication\Okta;

use SilverStripe\Core\Convert;
use SilverStripe\Core\Config\Config;
use SilverStripe\Security\Member;
use SilverStripe\ORM\DataList;

/**
 * Class providing common methods for Okta Application search, sync etc
 */
abstract class OktaAppClient extends OktaClient
{

    /**
     * A user assigned to an application directly
     */
    const APPUSER_SCOPE_USER = 'USER';

    /**
     * A user assigned to an application via a group
     */
    const APPUSER_SCOPE_GROUP = 'GROUP';

    /**
     * @var \Okta\Applications\Collection
     */
    protected $appUsers;

    /**
     * Client ID for the application resource
     */
    protected function getClientId() : string
    {
        $id = Config::inst()->get(ClientFactory::class, 'application_client_id');
        if(!$id) {
            throw new \Exception("No App ClientId configured (ClientFactory.application_client_id)");
        }
        return $id;
    }

    /**
     * Return the resource used to access Okta Application operations
     * @param object $properties passed during resource creation
     */
    final protected function getApplicationResource(object $properties = null) : \Okta\Applications\Application {
        if(!$properties) {
            $properties = new \stdClass;
        }
        if(empty($properties->id)) {
            $properties->id = $this->getClientId();
        }
        $resource = new \Okta\Applications\Application(null, $properties);
        return $resource;
    }

    /**
     * Collect all app users via pagination method
     * @param int $limit
     * @param array $queryOptions other filtering options (https://developer.okta.com/docs/reference/api/users/#list-users-with-a-filter). Can include limit (per page limit of resutls), after (cursor for next page of results)
     * @return void
     */
    final protected function getAppUsers(array $queryOptions = [])
    {

        // Initial set
        $this->appUsers = new \Okta\Applications\Collection([]);

        // Application resource
        $resource = $this->getApplicationResource();

        // initial options for initial request
        $options = ['query' => []];
        // merge in other options
        $options['query'] = array_merge($options['query'], $queryOptions);
        $this->collectAppUsers($options, $resource);
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
                // reset 'after' cursor value
                $this->cursorAfter = null;
                $options = $this->httpClient->getNextPageOptions();
                if(isset($options['after'])) {
                    // store 'after' cursor for next batch
                    $this->cursorAfter = $options['after'];
                }

                // Not single page request, get the next set
                if(!$this->singlePage) {
                    $this->collectAppUsers(['query' => $options ], $resource);
                }

            } catch (\Exception $e) {
                // getNextPageOptions threw an exception (or no more results)
            }
        }
        return false;
    }

    /**
     * Get a list of stale members, last OktaLastSync before the provided datetime
     * @param \DateTime
     * @param int $limit
     * @return DataList
     */
    public function getStaleMemberList(\DateTime $before, int $limit = 0) : DataList {
        // Members who have been sync'd
        $members = $this->getSyncedMembers();
        // last synced before the provided DateTime
        $members = $members->filter([ "OktaLastSync:LessThan" => $before->format('Y-m-d H:i:s') ]);
        $members = $members->setQueriedColumns(['OktaProfileLogin','OktaLastSync']);
        if($limit > 0) {
            $members = $members->limit($limit);
        }
        return $members;
    }

    /**
     * Get a list of members with an OktaLastSync before the provided DateTime
     * AND who are no longer linked to the configured Okta application clientId
     * For instance if a user was removed from the application, they will stop syncing
     * and their related Member record will be picked up here
     * @param DateTime check for members last sync'd before this datetime
     * @return DataList|null if null, there are no stale members to unlink
     */
    protected function getUnlinkedMembers(\DateTime $before, int $limit = 0) : ?DataList {
        $members = $this->getStaleMemberList($before, $limit);
        if($members->count() == 0) {
            // there are no stale members to unlink
            return null;
        }
        $clientId = $this->getClientId();
        $userResource = $this->getUserResource();
        $applicationResource = $this->getApplicationResource();
        $unlinkedMemberIds = [];
        foreach($members as $member) {
            try {
                $identifier = $member->OktaProfileLogin;
                $user = $userResource->get($identifier);
                try {
                    $userId = $user->getId();
                    $appUser = $applicationResource->getApplicationUser($userId);
                } catch (\Okta\Exceptions\ResourceException $e) {
                    if($e->getErrorCode() == self::RESOURCE_NOT_FOUND) {
                        Logger::log("Member #{$member->ID} - resource not found - application user");
                        $unlinkedMemberIds[] = $member->ID;
                    }
                }
            } catch (\Okta\Exceptions\ResourceException $e) {
                if($e->getErrorCode() == self::RESOURCE_NOT_FOUND) {
                    Logger::log("Member #{$member->ID} - resource not found - user");
                    $unlinkedMemberIds[] = $member->ID;
                }
            }
        }
        $unlinkedMembers = null;
        if(!empty($unlinkedMemberIds)) {
            // return the subset of the stale members
            // the segment not returned still exist in the application
            $unlinkedMembers = $members->filter(['ID' => $unlinkedMemberIds]);
        }
        return $unlinkedMembers;
    }

}
