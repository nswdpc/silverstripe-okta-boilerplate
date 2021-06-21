<?php

namespace NSWDPC\Authentication\Okta;

use SilverStripe\Core\Extension;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\LiteralField;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;

class OAuthLoginFormExtension extends Extension {

    /**
     * Modify actions, based on signed in/out state
     */
    public function updateFormActions(&$actions) {
        $member = Security::getCurrentUser();
        if($member && $member->exists()) {
            $logoutLink = Security::logout_url();
            $actions = FieldList::create([
                LiteralField::create(
                    'doLogout',
                    sprintf(
                        '<p id="doLogout"><a class="button" href="%s" target="_top">%s</a></p>',
                        $logoutLink,
                        _t('OAuth.LOGOUT', "Sign out")
                    )
                )
            ]);
        }
    }

}
