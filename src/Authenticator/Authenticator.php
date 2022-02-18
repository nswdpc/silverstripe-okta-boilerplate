<?php

namespace NSWDPC\Authentication\Okta;

use Bigfork\SilverStripeOAuth\Client\Authenticator\Authenticator as OAuthAuthenticator;
use SilverStripe\Security\Security;
use SilverStripe\Security\Authenticator as AuthenticatorInterface;
use SilverStripe\Security\MemberAuthenticator\LogoutHandler;

/**
 * Extend the default OAuth authenticator to provide a logout service
 * @note this can be removed when https://github.com/bigfork/silverstripe-oauth-login/issues/23 is resolved
 */
class Authenticator extends OAuthAuthenticator
{

    /**
     * Provide both a login and logout service
     * @inheritdoc
     */
    public function supportedServices()
    {
        return Authenticator::LOGIN | Authenticator::LOGOUT;
    }

    /**
     * If the OAuthAuthenticator is the only authenticator for logout
     * this provides a default logout handler so that users can log out
     * @inheritdoc
     */
    public function getLogoutHandler($link)
    {
        try {
            $authenticators = Security::singleton()->getApplicableAuthenticators( AuthenticatorInterface::LOGOUT );
            if(isset($authenticators['default'])) {
                // return the default logout handler
                return $authenticators['default']->getLogoutHandler($link);
            }
        } catch (\Exception $e) {
            // possibly no 'default' authenticator
        }
        // return a 'classic' LogoutHandler
        return LogoutHandler::create($link, $this);
    }

}
