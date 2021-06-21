<?php

namespace NSWDPC\Authentication\Okta;

use Bigfork\SilverStripeOAuth\Client\Authenticator\Authenticator as OAuthAuthenticator;
use SilverStripe\Security\MemberAuthenticator\LogoutHandler;

/**
 * Extend the default OAuth authenticator to provide a logout service
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
     * Log a locally signed in member out
     * The link will contain the authenticator name
     * @inheritdoc
     */
    public function getLogoutHandler($link)
    {
        return LogoutHandler::create($link, $this);
    }

}
