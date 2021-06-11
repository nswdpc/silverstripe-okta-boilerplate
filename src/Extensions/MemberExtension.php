<?php

namespace NSWDPC\Authentication\Okta;

use SilverStripe\ORM\DataExtension;
use SilverStripe\ORM\ManyManyList;
use SilverStripe\Security\Member;
use Symbiote\MultiValueField\Fields\KeyValueField;


/**
 * Updates member view in administration area
 */
class MemberExtension extends DataExtension
{
    
    /**
     * @var array
     */
    private static $db = [
        'OktaProfile' => 'MultiValueField',
        'OktaLastSync' => 'DBDatetime'
    ];
    
    public function updateCmsFields($fields)
    {
        $fields->removeByName('Passports');
        $fields->removeByName('OAuthSource');
        
        $fields->replaceField(
            'OktaProfile',
            $oktaProfileField = KeyValueField::create(
                'OktaProfile',
                _t('OKTA.PROFILE_FIELD_TITLE', 'Okta profile')
            )
        );
        $fields->addFieldToTab('Root.Okta', $oktaProfileField);
        $fields->makeFieldReadonly('OktaProfile');
    }

    /**
     * Get a Member's *direct* Okta groups, which excludes the root Okta group
     */
    public function getOktaGroups() : ManyManyList
    {
        return $this->owner->DirectGroups()->filter(['IsOktaGroup' => 1]);
    }
}
