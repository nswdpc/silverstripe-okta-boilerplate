<?php
namespace NSWDPC\Authentication\Okta;

use SilverStripe\Core\Extension;
use SilverStripe\Security\Member;
use SilverStripe\Security\Permission;

/**
 * Veto lost password requests for non-CMS users
 */
class LostPasswordHandlerExtension extends Extension
{

    /**
     * Veto or allow forgotPassword requests for a member
     * If a user is removed from Okta we need to block local access
     * for any local member account they may have
     * @param Member|null $member
     */
    public function forgotPassword(Member &$member = null) : bool {
        if ($member && !Permission::checkMember($member, 'CMS_ACCESS')) {
            // Members without these permissions cannot
            $member = null;
        }
        return true;
    }
}
