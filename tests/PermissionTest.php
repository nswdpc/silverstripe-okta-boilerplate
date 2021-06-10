<?php

namespace NSWDPC\Authentication\Okta\Tests;

use NSWDPC\Authentication\Okta\OktaPermissionEscalationException;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\Security\Group;
use SilverStripe\Security\Permission;
use SilverStripe\Security\PermissionRole;

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
}
