<?php

namespace NSWDPC\Authentication\Okta;

use SilverStripe\Core\Config\Configurable;
use SilverStripe\View\TemplateGlobalProvider;

/**
 * Provider a configuration service for setting access help links and such
 */
class AccessSupportAssistance implements TemplateGlobalProvider
{

    use Configurable;

    /**
     * @var string
     */
    private static $assistance_link = '';

    /**
     * Return the assistance link, entitised for a template
     */
    public static function get_assistance_link() {
        return htmlspecialchars(self::config()->get('assistance_link'));
    }

    /**
     * Add support assistance variables globally
     * @return array
     */
    public static function get_template_global_variables() {
        return array(
            'OAuthSupportAssistanceLink' => 'get_assistance_link',
        );
    }
}
