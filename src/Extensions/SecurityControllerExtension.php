<?php

namespace NSWDPC\Authentication\Okta;

use SilverStripe\Core\Extension;
use SilverStripe\View\Requirements;

/**
 * Security controller extension
 * @extends \SilverStripe\Core\Extension<(\SilverStripe\Security\Security & static)>
 */
class SecurityControllerExtension extends Extension
{
    public function onAfterInit()
    {
        Requirements::css(
            'nswdpc/silverstripe-okta-boilerplate:client/static/style/auth.css',
            'screen'
        );
    }
}
