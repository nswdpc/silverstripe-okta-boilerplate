<?php

namespace NSWDPC\Authentication\Okta;

use Bigfork\SilverStripeOAuth\Client\Model\Passport;
use Bigfork\SilverStripeOAuth\Client\Factory\ProviderFactory;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Core\Validation\ValidationException;
use SilverStripe\Forms\DropdownField;
use SilverStripe\Core\Extension;
use SilverStripe\Security\Member;
use SilverStripe\Security\Permission;
use SilverStripe\Security\PermissionProvider;
use SilverStripe\Security\Security;

/**
 * Adds the OauthSource to the Identifier to avoid collisions when
 * multiple Oauth providers are used
 *
 * Adds unique indexes to the DB
 * @author James
 * @property ?string $OAuthSource
 * @property int $CreatedByMemberID
 * @method \SilverStripe\Security\Member CreatedByMember()
 * @extends \SilverStripe\Core\Extension<(\Bigfork\SilverStripeOAuth\Client\Model\Passport & static)>
 */
class PassportExtension extends Extension implements PermissionProvider
{
    private static array $db = [
        'OAuthSource' => 'Varchar(255)'
    ];

    private static array $has_one = [
        'CreatedByMember' => Member::class
    ];

    private static array $indexes = [
        'Created' => true,
        'LastEdited' => true,
        'IdentifierProvider' => [
            'type' => 'unique',
            'columns' => [
                'Identifier',
                'OAuthSource'
            ]
        ]
    ];

    private static array $summary_fields = [
        'Identifier' => 'Identifier',
        'OAuthSource' => 'OAuth provider',
        'Member.Email' => 'Member',
        'Created' => 'Created',
        'LastEdited' => 'Edited',
        'CreatedByMember.Email' => 'Created by'
    ];

    private static array $searchable_fields = [
        'Identifier' => 'PartialMatchFilter',
        'OAuthSource' => 'ExactMatchFilter',
        'Member.Email' => 'PartialMatchFilter'
    ];

    /**
     * Validate the values provided prior to allowing write
     */
    public function validatePassportWrite(): bool
    {

        // Validate: the Identifier/OAuthSource is unique
        if ($this->getOwner()->Identifier && $this->getOwner()->OAuthSource) {
            $existing = Passport::get()->filter([
                'Identifier' => $this->getOwner()->Identifier,
                'OAuthSource' => $this->getOwner()->OAuthSource
            ]);
            if ($this->getOwner()->isInDB()) {
                // exclude current record if it exists
                $existing = $existing->exclude([ "ID" => $this->getOwner()->ID ]);
            }

            $existing = $existing->first();
            if ($existing && $existing->exists()) {
                throw ValidationException::create(OktaLoginHandler::getFailMessageForCode(OktaLoginHandler::FAIL_PASSPORT_CREATE_IDENT_COLLISION), OktaLoginHandler::FAIL_PASSPORT_CREATE_IDENT_COLLISION);
            }
        }

        // Validate: the MemberID/OAuthSource is unique
        if ($this->getOwner()->MemberID && $this->getOwner()->OAuthSource) {
            // validate member/provider passport does not exist
            $existing = Passport::get()->filter([
                'MemberID' => $this->getOwner()->MemberID,
                'OAuthSource' => $this->getOwner()->OAuthSource
            ]);
            if ($this->getOwner()->isInDB()) {
                // exclude current record if it exists (updating current record)
                $existing = $existing->exclude(["ID" => $this->getOwner()->ID ]);
            }

            $existing = $existing->first();
            if ($existing && $existing->exists()) {
                throw ValidationException::create(OktaLoginHandler::getFailMessageForCode(OktaLoginHandler::FAIL_USER_MEMBER_PASSPORT_MISMATCH), OktaLoginHandler::FAIL_USER_MEMBER_PASSPORT_MISMATCH);
            }
        }

        return true;
    }

    public function onBeforeWrite()
    {
        if (!$this->getOwner()->isInDB()) {
            $member = Security::getCurrentUser();
            $this->getOwner()->CreatedByMemberID = $member->ID ?? 0;
        }

        // validate that the passport can be written
        $this->validatePassportWrite();
    }

    public function getTitle()
    {
        if ($this->getOwner()->exists()) {
            return _t(
                'OAUTH.PASSPORT_TITLE',
                '{Identifier} @ {OAuthSource}',
                [
                    'Identifier' => $this->getOwner()->Identifier,
                    'OAuthSource' => $this->getOwner()->OAuthSource
                ]
            );
        } else {
            return _t('OKTA.NEW_PASSPORT', 'New OAuth Passport');
        }
    }

    /**
     * Members cannot edit a passport record
     */
    public function canEdit($member): bool
    {
        return false;
    }

    /**
     * Members cannot create a passport record
     */
    public function canCreate($member): bool
    {
        return false;
    }

    /**
     * Who can delete a passport
     */
    public function canDelete($member)
    {
        return Permission::checkMember($member, 'OAUTH_PASSPORT_EDIT');
    }

    /**
     * Who can view a passport
     */
    public function canView($member)
    {
        return Permission::checkMember($member, 'OAUTH_PASSPORT_VIEW');
    }

    /**
     * Update fields for CMS
     */
    public function updateCmsFields($fields)
    {
        if ($sourceField = $fields->dataFieldByName('OAuthSource')) {
            $providerFactory = Injector::inst()->get(ProviderFactory::class);
            $providers = $providerFactory->getProviders();
            $listProviders = [];
            if ($this->getOwner()->OAuthSource) {
                $listProviders[ $this->getOwner()->OAuthSource ] = _t(
                    'OKTA.PROVIDER_' . $this->getOwner()->OAuthSource,
                    $this->getOwner()->OAuthSource
                );
            }

            if (is_array($providers)) {
                foreach (array_keys($providers) as $providerName) {
                    $listProviders[ $providerName ] = _t(
                        'OKTA.PROVIDER_' . $providerName,
                        $providerName
                    );
                }
            }

            $fields->replaceField(
                'OAuthSource',
                DropdownField::create(
                    'OAuthSource',
                    _t('OAUTH.SOURCE_TITLE', 'OAuth provider'),
                    $listProviders,
                    $this->getOwner()->OAuthSource
                )->setEmptyString('')
            );
        }

        if (!$this->getOwner()->isInDB()) {
            $fields->removeByName('CreatedByMemberID');
        } elseif ($createdByMemberField = $fields->dataFieldByName('CreatedByMemberID')) {
            $createdByMemberField->setTitle(_t('OAUTH.CREATED_BY_MEMBER', 'Created by'));
            $fields->makeFieldReadonly('CreatedByMemberID');
        }
    }

    /**
     * Provide permissions for passports
     */
    public function providePermissions()
    {
        return [
            'OAUTH_PASSPORT_VIEW' => [
                'name' => _t('OAUTH.PERMISSION_VIEW', 'View OAuth passports'),
                'category' => 'OAuth',
            ],
            'OAUTH_PASSPORT_EDIT' => [
                'name' => _t('OAUTH.PERMISSION_CED', 'Create and delete OAuth passports'),
                'category' => 'OAuth',
            ],
            'OAUTH_SYNC_REPORT_VIEW' => [
                'name' => _t('OAUTH.SYNC_REPORT_VIEW', 'View sync report'),
                'category' => 'OAuth',
            ]
        ];
    }
}
