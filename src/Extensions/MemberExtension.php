<?php
namespace NSWDPC\Authentication\Okta;

use SilverStripe\ORM\DataExtension;
use SilverStripe\Security\Member;

/**
 * Updates member view in administration area
 */
class MemberExtension extends DataExtension
{

    public function updateCmsFields($fields) {
        $fields->removeByName('Passports');
        $fields->removeByName('OAuthSource');
    }
}
