<?php
namespace NSWDPC\Authentication\Okta;

use SilverStripe\ORM\DataExtension;

/**
 * Adds the OauthSource to the Identifier to avoid collisions when
 * multiple Oauth providers are used
 * @author James
 */
class PassportExtension extends DataExtension {

    private static $db = [
        'OAuthSource' => 'Varchar(255)'
    ];

    private static $indexes = [
        'IdentifierProvider' => [
            'type' => 'unique',
            'columns' => [
                'Identifier',
                'OAuthSource'
            ]
        ]
    ];

}
