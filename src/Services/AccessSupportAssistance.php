<?php

declare(strict_types=1);

namespace NSWDPC\Authentication\Okta;

use SilverStripe\Core\Config\Configurable;
use SilverStripe\View\TemplateGlobalProvider;

/**
 * Provider a configuration service for setting access help links and such
 */
class AccessSupportAssistance implements TemplateGlobalProvider
{
    use Configurable;

    private static string $assistance_link = '';

    /**
     * Return the assistance link, entitised for a template
     */
    public static function get_assistance_link(): string
    {
        return htmlspecialchars((string) self::config()->get('assistance_link'));
    }

    /**
     * Add support assistance variables globally
     * @return array
     */
    public static function get_template_global_variables()
    {
        return [
            'OAuthSupportAssistanceLink' => 'get_assistance_link',
        ];
    }
}
