<?php

namespace NSWDPC\Authentication\Okta;

use Bigfork\SilverStripeOAuth\Client\Model\Passport;
use SilverStripe\Admin\ModelAdmin;
use SilverStripe\Forms\GridField\GridFieldAddNewButton;
use SilverStripe\Forms\GridField\GridFieldPrintButton;
use SilverStripe\Forms\GridField\GridFieldExportButton;

/**
 * Administration area for OAuth2 providers
 */
class OAuthAdmin extends ModelAdmin
{
    /**
     * @inheritdoc
     */
    public $showImportForm = false;

    private static string $url_segment = 'oauth';

    private static string $menu_title = 'OAuth';

    private static string $menu_icon = 'nswdpc/silverstripe-okta-boilerplate:client/static/images/oauth_logo_final.png';

    private static array $managed_models = [
        Passport::class,
        OAuthLog::class
    ];

    #[\Override]
    public function getEditForm($id = null, $fields = null)
    {
        if ($this->modelClass == OAuthLog::class) {
            OAuthLog::truncate();
        }

        $form = parent::getEditForm($id, $fields);
        /** @var \SilverStripe\Forms\GridField\GridField  $grid **/
        $grid = $form->Fields()->dataFieldByName($this->sanitiseClassName($this->modelClass));
        $config = $grid->getConfig();
        $config->removeComponentsByType(GridFieldPrintButton::class);
        $config->removeComponentsByType(GridFieldExportButton::class);
        $config->removeComponentsByType(GridFieldAddNewButton::class);
        return $form;
    }
}
