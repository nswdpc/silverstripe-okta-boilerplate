<?php

namespace NSWDPC\Authentication\Okta;

use SilverStripe\ORM\DataExtension;
use SilverStripe\ORM\ManyManyList;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\ORM\FieldType\DBField;
use SilverStripe\Forms\ReadonlyField;
use SilverStripe\Forms\CompositeField;
use SilverStripe\Forms\CheckboxField;
use SilverStripe\Forms\LabelField;
use SilverStripe\Forms\LiteralField;
use SilverStripe\Security\Member;
use SilverStripe\Security\Permission;
use SilverStripe\Security\PermissionProvider;
use SilverStripe\Security\Security;
use PhpTek\JSONText\ORM\FieldType\JSONText;

/**
 * Updates member view in administration area
 */
class MemberExtension extends DataExtension implements PermissionProvider
{

    /**
     * @var array
     */
    private static $db = [
        'OktaProfileValue' => JSONText::class,
        // see https://developer.okta.com/docs/reference/api/users/#profile-object
        'OktaProfileLogin' => 'Varchar(100)',
        'OktaLastSync' => 'DBDatetime',
        'OktaUnlinkedWhen' => 'DBDatetime'
    ];

    /**
     * @var array
     */
    private static $indexes = [
        'OktaLastSync' => true,
        'OktaUnlinkedWhen' => true,
        'OktaProfileLogin' => [
            'type' => 'unique',
            'columns' => [
                'OktaProfileLogin'
            ]
        ]
    ];

    /**
     * Default profile fields stored during sync
     * See: https://developer.okta.com/docs/reference/api/users/#default-profile-properties
     * @var array
     */
    private static $okta_profile_fields = [];

    /**
     * Handle member okta operations on write
     */
    public function onBeforeWrite()
    {
        parent::onBeforeWrite();
        if ($this->owner->OktaLastSyncClear) {
            $this->owner->OktaLastSync = null;
        }
    }

    /**
     * Reset values after write
     */
    public function onAfterWrite()
    {
        parent::onAfterWrite();
        $this->owner->OktaLastSyncClear = null;
    }

    /**
     * Check if the lost password email can be sent
     * @todo exclude ADMIN permission members (return false ?)
     * @return bool
     */
    public static function canSendLostPasswordEmail(Member $member) {
        // handler is trying to send a lost password email
        if(Permission::checkMember($member, 'OKTA_LOCAL_PASSWORD_RESET')) {
            // This specific member has a permission to allow local password reset
            return true;
        } else {
            return false;
        }
    }

    /**
     * Test external management context for this member
     * This is used to flag that the person can manage their member record externally
     * In the case of Okta, this is all contexts
     * @return bool
     */
    public function isExternallyManagedContext($context) : bool {

        if($context == 'lostPasswordSendEmail') {
            $canSend = self::canSendLostPasswordEmail($this->owner);
            if($canSend) {
                // local password reset allowed in this context
                return false;
            }
        }
        // default: all contexts are externally managed
        return $this->owner->OktaProfileLogin != '';
    }

    /**
     * Get a passport for the member
     * @param string $provider the provider name
     */
    public function getPassport(string $provider)
    {
        if ($passports = $this->owner->Passports()) {
            return $passports->filter('OAuthSource', $provider)->first();
        } else {
            return null;
        }
    }

    /**
     * Setter for OktaProfileValue JSONText field
     * The passed value can either be an array or an {@link \Okta\Users\UserProfile}
     * The configuration value of `Silverstripe\Security\Members.okta_profile_fields`
     * determines what profile fields are stored
     */
    public function setOktaProfileValue($value) {
        $profileValue = [];
        $profileFields = $this->owner->config()->get('okta_profile_fields');
        if(!is_array($profileFields)) {
            $profileFields = [];
        }
        if($value instanceof \Okta\Users\UserProfile) {
            foreach($profileFields as $profileFieldName => $profileFieldMeta) {
                $profileValue[ $profileFieldName ] = $value->getProperty($profileFieldName);
            }
        } else if(is_array($value)) {
            // Parameter is a key value pair
            foreach($profileFields as $profileFieldName => $profileFieldMeta) {
                $profileValue[ $profileFieldName ] = isset($value[ $profileFieldName ]) ? $value[ $profileFieldName ] : null;
            }
        }
        ksort($profileValue);
        $this->owner->setField(
            'OktaProfileValue',
            json_encode($profileValue)
        );
        return true;
    }

    /**
     * Return OktaProfileValue as an array
     * @return array
     * @throws \Exception
     */
    public function getOktaProfileValueAsArray() : ?array {
        $value = json_decode($this->owner->OktaProfileValue, true, JSON_THROW_ON_ERROR);
        if(!is_array($value)) {
            $value = [];
        }
        return $value;
    }

    /**
     * Return a formatted OktaProfileValue for display in a readable format
     */
    public function formatOktaProfileValue() : string {
        $formattedValue = '';
        if($this->owner->OktaProfileValue) {
            try {
                $formattedValue = json_encode(
                    $this->owner->getOktaProfileValueAsArray(),
                    JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR
                );
            } catch (\Exception $e) {
            }
        }
        return $formattedValue;
    }

    public function updateCmsFields($fields)
    {
        $fields->removeByName([
            'Passports',
            'Okta',
            'OAuthSource',
            'OktaProfileLogin',
            'OktaProfileValue',
            'OktaLastSync',
            'OktaUnlinkedWhen'
        ]);

        if( Permission::checkMember( Security::getCurrentUser(), 'ADMIN') ) {
            $fields->addFieldToTab(
                'Root.Okta',
                CompositeField::create(
                    ReadonlyField::create(
                        'OktaProfileLogin',
                        _t('OKTA.PROFILE_LOGIN', 'Okta login')
                    ),
                    LabelField::create(
                        'OktaProfileLabel',
                        _t('OKTA.PROFILE_FIELD_TITLE', 'Latest profile data')
                    ),
                    LiteralField::create(
                        'OktaProfileValue',
                        '<pre>' . htmlspecialchars($this->formatOktaProfileValue()) . '</pre>'
                    ),
                    CompositeField::create(
                        ReadonlyField::create(
                            'OktaLastSync',
                            _t('OKTA.LAST_SYNC_DATETIME', 'Last sync. date'),
                            $this->owner->OktaLastSync
                        ),
                        CheckboxField::create(
                            'OktaLastSyncClear',
                            _t(
                                'OKTA.CLEAR_SYNC_DATETIME',
                                'Clear this value'
                            )
                        )
                    ),
                    ReadonlyField::create(
                        'OktaUnlinkedWhen',
                        _t('OKTA.UNLINKED_DATETIME', 'When this member was unlinked from an Okta profile')
                    ),
                )->setTitle(
                    _t('OKTA.OKTA_HEADING', 'Okta')
                )
            );
        }
    }

    /**
     * Extend {@link Member::validateCanLogin()} to block logins for anyone whose account has become stale
     * @return void
     */
    public function canLogIn(ValidationResult &$result)
    {

        /**
         * If the validation result is already a fail, go no further
         */
        if (!$result->isValid()) {
            return false;
        }

        $days = intval($this->owner->config()->get('okta_lockout_after_days'));
        if ($days <= 0) {
            // if the configured days is 0 or less, OK
            return true;
        }
        if (!$this->owner->OktaLastSync) {
            // If the member has never been sync'd, allow
            return;
        }

        // calculate datetime comparison
        try {
            $dt = new \DateTime();
            $odt = new \DateTime($this->owner->OktaLastSync);
            $odt->modify("+1 {$days} day");
            if ($odt < $dt) {
                // still not on or after today
                $result->addError(
                    _t(
                        'OKTA.ACCOUNT_TOO_OLD',
                        'Sorry, you cannot sign in to this website as your account has not been used recently.'
                        . ' Please contact a website administrator for further assistance.'
                    )
                );
                return false;
            }
        } catch (\Exception $e) {
            // noop
        }
        return true;
    }

    /**
     * Get a Member's *direct* Okta groups, which excludes the root Okta group
     */
    public function getOktaGroups() : ManyManyList
    {
        return $this->owner->DirectGroups()->filter(['IsOktaGroup' => 1]);
    }

    /**
     * Provide permissions
     */
    public function providePermissions()
    {
        return [
            'OKTA_LOCAL_PASSWORD_RESET' => [
                'name' => _t('OKTA.ALLOW_LOCAL_PASSWORD_RESET', 'Allow local password reset'),
                'category' => _t(
                    'SilverStripe\\Security\\Permission.PERMISSIONS_CATEGORY',
                    'Roles and access permissions'
                ),
            ]
        ];
    }

}
