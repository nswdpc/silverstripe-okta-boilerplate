<?php

namespace NSWDPC\Authentication\Okta;

use SilverStripe\ORM\DataExtension;
use SilverStripe\ORM\ManyManyList;
use SilverStripe\Security\Member;

/**
 * Updates member view in administration area
 */
class MemberExtension extends DataExtension
{
    public function updateCmsFields($fields)
    {
        $fields->removeByName('Passports');
        $fields->removeByName('OAuthSource');
    }

    /**
     * Get a Member's *direct* Okta groups, which excludes the root Okta group
     */
    public function getOktaGroups() : ManyManyList
    {
        return $this->owner->DirectGroups()->filter(['IsOktaGroup' => 1]);
    }
}
