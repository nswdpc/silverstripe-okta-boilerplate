<?php

namespace NSWDPC\Authentication\Okta\Tests;

use NSWDPC\Authentication\Okta\OktaPermissionEscalationException;
use SilverStripe\Control\Controller;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\Security\Group;
use SilverStripe\Security\Member;
use SilverStripe\Security\Permission;
use SilverStripe\Security\PermissionRole;
use SilverStripe\Security\MemberAuthenticator\MemberAuthenticator;
use SilverStripe\Security\MemberAuthenticator\LostPasswordHandler;
use SilverStripe\Security\MemberAuthenticator\LostPasswordForm;

/**
 * Run test related to the Okta API using `okta/sdk`
 */
class PermissionTest extends SapphireTest
{
    protected $usesDatabase = true;

    public function testGroupPermission()
    {
        try {
            $group = Group::create([
                'Code' => 'oktagroup',
                'Title' => 'Test okta group',
                'IsOktaGroup' => 1
            ]);
            $permissionAdmin = Permission::get()->filter('Code', 'ADMIN')->first();
            $group->Permissions()->add($permissionAdmin);
            $group->write();
            $this->assertFalse(true, 'Okta group write with a permission should have failed');
        } catch (\Exception $e) {
            $this->assertInstanceOf(OktaPermissionEscalationException::class, $e);
        }
        $postGroup = Group::get()->filter(['Code' => 'oktagroup'])->first();
        $this->assertEmpty($postGroup, "Group exists!");
    }

    public function testGroupRoles()
    {
        try {
            $group = Group::create([
                'Code' => 'oktagroup',
                'Title' => 'Test okta group',
                'IsOktaGroup' => 1
            ]);
            $permissionRole = PermissionRole::create(['Title' => 'A role']);
            $permissionRole->write();
            $group->Roles()->add($permissionRole);
            $group->write();
            $this->assertFalse(true, 'Okta group write with a role should have failed');
        } catch (\Exception $e) {
            $this->assertInstanceOf(OktaPermissionEscalationException::class, $e);
        }
        $postGroup = Group::get()->filter(['Code' => 'oktagroup'])->first();
        $this->assertEmpty($postGroup, "Group exists!");
    }

    /**
     * Test ability to reset a local password
     */
    public function testPasswordReset() {

        $passwordUpdaters = Group::create([
            'Title' => 'Local password updaters',
        ]);
        $passwordUpdaters->write();
        Permission::grant($passwordUpdaters->ID, 'OKTA_LOCAL_PASSWORD_RESET');


        $editorsGroup = Group::create([
            'Title' => 'Editors',
        ]);
        $editorsGroup->write();
        Permission::grant($editorsGroup->ID, 'CMS_ACCESS_CMSMain');

        $canUpdatePassword = Member::create([
            'FirstName' => "Password",
            "Surname" => "Resetter",
            "Email" => "resetter@example.com"
        ]);
        $canUpdatePassword->write();
        $passwordUpdaters->Members()->add($canUpdatePassword);

        $cannotUpdatePassword = Member::create([
            'FirstName' => "Password",
            "Surname" => "Not-Resetter",
            "Email" => "resetter.not@example.com"
        ]);
        $cannotUpdatePassword->write();

        // create an editor
        $isEditor = Member::create([
            'FirstName' => "Yoda",
            "Surname" => "Editor",
            "Email" => "editor.iam@example.com"
        ]);
        $isEditor->write();
        $editorsGroup->Members()->add($isEditor);

        $link = "/fake/link";
        $passwordSent = "/fake/link/passwordsent";

        $handler = LostPasswordHandler::create($link);
        $controller = Controller::curr();

        $form = LostPasswordForm::create(
            $controller,
            MemberAuthenticator::class,
            "LostPasswordForm"
        );

        $response = $handler->forgotPassword([
            'Email' => $canUpdatePassword->Email
        ], $form);

        $statusCode = $response->getStatusCode();
        $this->assertEquals(302, $statusCode);
        $this->assertTrue( strpos( $response->getHeader("Location"), $passwordSent) !== false, "redirect URL should contain '{$passwordSent}" );

        $email = $this->findEmail($canUpdatePassword->Email);

        $this->assertNotEmpty($email, "A password reset email should have been sent for canUpdatePassword");

        Permission::deny($passwordUpdaters->ID, 'OKTA_LOCAL_PASSWORD_RESET');

        $response = $handler->forgotPassword([
            'Email' => $cannotUpdatePassword->Email
        ], $form);

        // people who cannot update password should still get this page
        $statusCode = $response->getStatusCode();
        $this->assertEquals(302, $statusCode);
        $this->assertTrue( strpos( $response->getHeader("Location"), $passwordSent) !== false, "redirect URL should contain '{$passwordSent}' for cannotUpdatePassword" );

        $email = $this->findEmail($cannotUpdatePassword->Email);

        $this->assertEmpty($email, "A password reset email should not have been sent for cannotUpdatePassword");

        // test editor
        $response = $handler->forgotPassword([
            'Email' => $isEditor->Email
        ], $form);

        // people who cannot update password should still get this page
        $statusCode = $response->getStatusCode();
        $this->assertEquals(302, $statusCode);
        $this->assertTrue( strpos( $response->getHeader("Location"), $passwordSent) !== false, "redirect URL should contain '{$passwordSent}' for isEditor" );

        $email = $this->findEmail($isEditor->Email);

        $this->assertNotEmpty($email, "A password reset email should have been sent for isEditor");


    }
}
