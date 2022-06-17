<?php

namespace NSWDPC\Authentication\Okta;

use SilverStripe\Core\Extension;
use SilverStripe\Security\Member;
use SilverStripe\Security\Permission;

/**
 * Veto lost password requests for non-CMS users
 * @todo make generic
 */
class LostPasswordHandlerExtension extends Extension
{

    /**
     * Veto or allow forgotPassword requests for a member
     * @param Member|null $member
     */
    public function forgotPassword(Member &$member = null) : bool
    {
        if($member && Permission::checkMember($member, 'OKTA_LOCAL_PASSWORD_RESET')) {
            // Members with this permission may reset a local password
            return true;
        } else {
            // remove the member record
            $member = null;
        }
        return true;
    }
}
