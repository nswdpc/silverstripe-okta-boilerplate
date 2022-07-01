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
     * @deprecated note that this method will be removed in a future major release
     *              Project code should lean on isExternallyManagedContext extension method
     *              on Member and provide a context of 'lostPasswordSendEmail'
     * @param Member|null $member
     */
    public function forgotPassword(Member &$member = null) : bool
    {
        if($member) {
            $canSend = MemberExtension::canSendLostPasswordEmail($member);
            if($canSend) {
                // permissions allow
                return true;
            } else {
                // remove the member record, avoid sending email
                $member = null;
            }
        }
        // default: no action
        return true;
    }
}
