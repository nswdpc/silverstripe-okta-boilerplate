<?php
namespace NSWDPC\Authentication\Okta;

use SilverStripe\ORM\DataExtension;

/**
 * Adds the OauthSource to the Identifier to avoid collisions when
 * multiple Oauth providers are used
 *
 * Adds unique indexes to the DB
 * @author James
 */
class PassportExtension extends DataExtension {

    /**
     * @var array
     */
    private static $db = [
        'OAuthSource' => 'Varchar(255)'
    ];

    /**
     * @var array
     */
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
