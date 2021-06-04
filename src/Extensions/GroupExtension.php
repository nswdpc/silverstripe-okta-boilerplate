<?php
namespace NSWDPC\Authentication\Okta;

use SilverStripe\Core\Convert;
use SilverStripe\Core\Config\Config;
use SilverStripe\ORM\DataExtension;
use SilverStripe\Forms\ReadonlyField;
use SilverStripe\Security\Group;

/**
 * Update group handling to include Okta group support
 * @author James
 */
class GroupExtension extends DataExtension {

    /**
     * @var array
     */
    private static $db = [
        'IsOktaGroup' => 'Boolean'
    ];

    /**
     * @var array
     */
    private static $indexes = [
        'IsOktaGroup' => true, // query on IsOktaGroup
        'Title' => true // need to query on title
    ];

    /**
     * Add/edit CMS fields
     */
    public function updateCmsFields($fields) {
        $fields->addFieldToTab(
            'Root.Main',
            ReadonlyField::create(
                'IsOktaGroup'
            )->setDescription(
                _t(
                    'OKTA.IS_OKTA_GROUP_DESCRIPTION',
                    'This group was synchronised from Okta'
                )
            ),
            'Description'
        );
    }

    /**
     * Require default records on dev build
     */
    public function requireDefaultRecords() {
        $this->owner->applyOktaRootGroup();
    }

    /**
     * Create or update the default root Okta group configured, if set
     * @return Group|null
     */
    public function applyOktaRootGroup() {
        $parent = $this->owner->config()->get('okta_group');
        if(empty($parent['Code'])) {
            return;
        }
        $group = Group::get()->filter( [ 'Code' => Convert::raw2url($parent['Code']) ] )->first();
        if(!$group) {
            $group = Group::create($parent);
            $group->IsOktaGroup = 1;
            $group->ParentID = 0;
            $group->write();
        } else {
            if(isset($parent['Title'])) {
                $group->Title = $parent['Title'];
            }
            if(isset($parent['Description'])) {
                $group->Description = $parent['Description'];
            }
            $group->Locked = $parent['Locked'] ?? 1;
            $group->Code = $parent['Code'];
            $group->IsOktaGroup = 1;
            $group->ParentID = 0;
            $group->write();
        }
        return $group;
    }

}
