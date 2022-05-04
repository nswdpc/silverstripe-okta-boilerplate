<?php

namespace NSWDPC\Authentication\Okta;

use SilverStripe\Control\HTTPRequest;
use SilverStripe\Security\Member;

/**
 * Search for users in an Okta Application via Okta API
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
        // ensure values are correctly encoded
        $queryOptions = array_map(
            function($value) {
                return rawurldecode($value);
            },
            $queryOptions
        );
        // set default limit
        $queryOptions['limit'] = $this->defaultLimit;
        $this->getAppUsers($queryOptions);
        return $this->appUsers;
    }

}
