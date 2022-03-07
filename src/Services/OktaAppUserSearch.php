<?php

namespace NSWDPC\Authentication\Okta;

use SilverStripe\Control\HTTPRequest;
use SilverStripe\Security\Member;

/**
 * Search for users in Okta via Okta API
 * @author James
 */
class OktaAppUserSearch extends OktaAppClient
{

    /**
     * Search for users in Okta application based on parameters provided in $request
     * @param array $queryOptions sent to the Okta endpoint
     * See: https://developer.okta.com/docs/reference/api/users/#find-users
     * See: https://developer.okta.com/docs/reference/api/users/#list-users-with-a-filter
     * See: https://developer.okta.com/docs/reference/api/users/#list-users-with-search
     */
    public function search(array $queryOptions) : ?\Okta\Applications\Collection {
        // Initial set
        $this->appUsers = new \Okta\Applications\Collection([]);
        // create/configure the Okta client
        $client = $this->getClient();
        // options for the search
        $limit = $this->defaultLimit;
        // ensure values are correctly encoded
        $queryOptions = array_map(
            function($value) {
                return rawurldecode($value);
            },
            $queryOptions
        );
        $this->getAppUsers($limit, $queryOptions);
        return $this->appUsers;
    }

}
