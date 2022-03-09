<?php

namespace NSWDPC\Authentication\Okta;

use SilverStripe\Core\Config\Config;

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
     * @param array $queryOptions other filtering options (https://developer.okta.com/docs/reference/api/users/#list-users-with-a-filter)
     * @return void
     */
    final protected function getAppUsers(int $limit = 50, array $queryOptions = [])
    {

        // Initial set
        $this->appUsers = new \Okta\Applications\Collection([]);

        // Application resource
        $resource = $this->getApplicationResource();

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

}
