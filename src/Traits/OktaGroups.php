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
     * Assign the Okta root group to the member
     */
    protected function assignOktaRootGroup(Member $member) : bool {
        $parentOktaGroup = GroupExtension::applyOktaRootGroup();
        if ($parentOktaGroup && $parentOktaGroup->isInDB()) {
            $member->Groups()->add( $parentOktaGroup );
            return true;
        }
        return false;
    }

}
