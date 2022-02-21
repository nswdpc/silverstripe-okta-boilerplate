<?php

namespace NSWDPC\Authentication\Okta;

use SilverStripe\Core\Convert;
use SilverStripe\Core\Config\Config;
use SilverStripe\ORM\DataExtension;
use SilverStripe\ORM\ValidationException;
use SilverStripe\ORM\FieldType\DBBoolean;
use SilverStripe\ORM\FieldType\DBField;
use SilverStripe\Forms\ReadonlyField;
use SilverStripe\Security\Group;

/**
 * Update group handling to include Okta group support
 * @author James
 */
class GroupExtension extends DataExtension
{

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
     * Default group title, if none provided in configuration
     */
    const DEFAULT_GROUP_TITLE = 'Okta';

    /**
     * Handle pre-write logic for OktaGroups
     * Any group that is marked an Okta group may not be assigned permissions or roles
     * Okta groups are solely for grouping users and/or targeted content
     */
    public function onBeforeWrite()
    {
        parent::onBeforeWrite();
        if ($this->owner->IsOktaGroup) {
            // avoid writing an OktaGroup with permissions
            $permissionCount = $this->owner->Permissions()->count();
            if ($permissionCount > 0) {
                throw new OktaPermissionEscalationException(
                    _t(
                        'OKTA.OKTA_GROUP_NO_PERMISSIONS',
                        "An Okta group may not be assigned permissions"
                    )
                );
            }
            $roleCount = $this->owner->Roles()->count();
            if ($roleCount > 0) {
                throw new OktaPermissionEscalationException(
                    _t(
                        'OKTA.OKTA_GROUP_NO_ROLES',
                        "An Okta group may not be assigned roles"
                    )
                );
            }
        }
    }

    /**
     * Add/edit CMS fields
     */
    public function updateCmsFields($fields)
    {
        $fields->removeByName('IsOktaGroup');
        $fields->addFieldToTab(
            'Root.Members',
            ReadonlyField::create(
                'IsOktaGroupLabel',
                _t('OKTA.OKTA_GROUP', 'Okta group')
            )->setDescription(
                _t(
                    'OKTA.IS_OKTA_GROUP_DESCRIPTION',
                    'This group was synchronised from Okta'
                )
            )->setValue(
                DBField::create_field(DBBoolean::class, $this->owner->IsOktaGroup)->Nice()
            ),
            'Description'
        );
    }

    /**
     * Require default records on dev build
     */
    public function requireDefaultRecords()
    {
        $this->owner->applyOktaRootGroup();
    }

    /**
     * Create or update the default root Okta group configured, if set
     * @return Group|null
     */
    public function applyOktaRootGroup() : ?Group
    {
        $parent = $this->owner->config()->get('okta_group');
        if (empty($parent['Code'])) {
            return null;
        }
        $code = Convert::raw2url($parent['Code']);
        $group = Group::get()->filter([ 'Code' => $code ])->first();
        $title = trim( !empty($parent['Title']) ? $parent['Title'] : '' );
        if($title == '') {
            $title = self::DEFAULT_GROUP_TITLE;
        }
        // Create a new group if none exists
        if (!$group) {
            $group = Group::create();
            if (!empty($parent['Description'])) {
                $group->Description = $parent['Description'];
            }
        }
        // Allow group title updates from configuration
        $group->Title = $title;
        $group->IsOktaGroup = 1;
        $group->ParentID = 0;
        $group->Locked = $parent['Locked'] ?? 1;
        // ensure code is set as it is stored in configuration
        $group->setField('Code', $code);
        $group->write();
        return $group;
    }

}
