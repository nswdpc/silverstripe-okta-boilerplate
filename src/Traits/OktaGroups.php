<?php

namespace NSWDPC\Authentication\Okta;

use SilverStripe\Security\Group;
use SilverStripe\Security\Member;

/**
 * This trait is used by Okta handlers that deal with linking an Okta user's groups
 * with their local Member Groups
 */
trait OktaGroups
{

    /**
     * Given an array of Okta groups found for an user, assign those groups to the Member
     * If the member already has Okta groups, remove those not found in $groups
     * @param array $groups values are Okta group names. Okta login handler does not return Okta group ids
     * @param Member $member
     * @return array values are created or updated Group.ID values for the $member
     */
    protected function oktaUserMemberGroupAssignment(array $groups, Member $member)
    {

        // @var \SilverStripe\ORM\ManyManyList
        // the current member Okta groups
        $currentMemberGroups = $member->getOktaGroups();
        // store groups created or updated
        $createdOrUpdatedGroups = [];

        // the Okta user returned some groups
        if (!empty($groups)) {
            $parent = GroupExtension::applyOktaRootGroup();
            if ($parent && $parent->isInDB()) {
                foreach ($groups as $oktaGroupName) {

                    // check for existing group
                    $group = Group::get()->filter([
                        'Title' => $oktaGroupName,
                        'IsOktaGroup' => 1
                    ])->first();

                    if (empty($group->ID)) {
                        // create this local group
                        $group = Group::create();
                        $group->ParentID = $parent->ID;
                        $group->IsOktaGroup = 1;
                        $group->Title = $oktaGroupName;
                        $group->Description = _t(
                            'OKTA.GROUP_DESCRIPTION_IMPORT',
                            'This group was imported from Okta'
                        );
                        $group->write();
                    }

                    // ensure Member linked to group
                    $member->Groups()->add($group);

                    // store created/update groups
                    $createdOrUpdatedGroups[] = $group->ID;
                }
            }
        }

        // if the Member had any groups to start with
        if ($currentMemberGroups->count() > 0) {

            // check whether any groups were created or updated
            if (!empty($createdOrUpdatedGroups)) {
                // get the groups that were not created or updated
                $groupsToUnlink = $currentMemberGroups->exclude(['ID' => $createdOrUpdatedGroups]);
            } else {
                // no local groups were created or updated, unlink all from the member groups list
                $groupsToUnlink = $currentMemberGroups;
            }

            // remove the unlinked groups from the
            foreach ($groupsToUnlink as $groupToUnlink) {
                // the group is retained, only the link to the $member is removed
                $currentMemberGroups->remove($groupToUnlink);
            }
        }

        return $createdOrUpdatedGroups;
    }
}
