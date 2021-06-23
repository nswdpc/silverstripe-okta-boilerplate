<?php

namespace NSWDPC\Authentication\Okta;

use Bigfork\SilverStripeOAuth\Client\Model\Passport;
use SilverStripe\Admin\ModelAdmin;
use SilverStripe\Security\Member;
use SilverStripe\Security\Group;
use SilverStripe\Security\Permission;
use SilverStripe\Control\Controller;
use SilverStripe\Forms\GridField\GridField;
use SilverStripe\Forms\GridField\GridFieldAddNewButton;
use SilverStripe\Forms\GridField\GridFieldDataColumns;
use SilverStripe\Forms\GridField\GridFieldPrintButton;
use SilverStripe\Forms\GridField\GridFieldDeleteAction;
use SilverStripe\Forms\GridField\GridFieldEditButton;
use SilverStripe\Forms\GridField\GridFieldExportButton;
use SilverStripe\Forms\GridField\GridFieldDetailForm;

/**
 * Administration area for OAuth2 providers
 */
class OAuthAdmin extends ModelAdmin
{
    /**
     * @inheritdoc
     */
    public $showImportForm = false;

    private static $url_segment = 'oauth';

    private static $menu_title = 'OAuth';

    private static $menu_icon = 'nswdpc/silverstripe-okta-boilerplate:client/static/images/oauth_logo_final.png';

    private static $managed_models = [
        Passport::class,
        OAuthLog::class
    ];

    public function getEditForm($id = null, $fields = null)
    {
        if ($this->modelClass == OAuthLog::class) {
            OAuthLog::truncate();
        }

        $form = parent::getEditForm($id, $fields);
        $grid = $form->Fields()->dataFieldByName($this->sanitiseClassName($this->modelClass));
        $config = $grid->getConfig();
        $config->removeComponentsByType(GridFieldPrintButton::class);
        $config->removeComponentsByType(GridFieldExportButton::class);
        $config->removeComponentsByType(GridFieldAddNewButton::class);
        return $form;
    }
}
