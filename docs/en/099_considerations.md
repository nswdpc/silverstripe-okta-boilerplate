# Considerations

## Other providers

You may have success using this module with other OAuth provider clients configured. If you do so, pay attention to the changes documented below.

The Okta login handler provided in this module works on the basis that:

1. The Okta user's preferred username is returned during the authentication process
1. One person is the owner of the Okta account and Silverstripe Member record

## Extensions

The following extensions and handlers modify or add functionality to the default OAuth process in Silverstripe. If you have other OAuth2 providers configured you should be aware of these changes:

### Group extension

The module adds an `IsOktaGroup` field and a default Okta group is created.

### Member extension

Adds OktaProfile and OktaLastSync fields.

### Passport extension

The module adds the OAuthSource value to the Passport and creates a unique index on Identifier + OAuthSource.

See OktaLoginHandler for usage.

## Okta Login Handler

Configuration adds this handler as the OAuth login handler when enabled. It overrides Passport and Member handling.

## Okta Linker

### update_existing_member

> Previously `NSWDPC\Authentication\Okta\OktaLoginHandler.link_existing_member`)

+ Value: true|false
+ Default: true

If true, existing members will be linked to authenticated Okta users based on their `Member.OktaProfileLogin` value. This is useful if you have an existing table of Silverstripe members.

If false, authenticated Okta users who have a matching Member record will have the following base Member fields updated from the Okta profile returned:

+ FirstName
+ Surname
+ Email (when a new member is created)

### link_via_email

+ Value: true|false
+ Default: false

Prior to setting this to true, read: https://developer.okta.com/docs/reference/api/oidc/#scope-dependent-claims-not-always-returned

> User's preferred email address. The resource provider must not rely on this value being unique.

Set this to true if your Okta login values will match Member.Email values.

The default is false, which will match Okta login values against Member.OktaProfileLogin value.

This configuration setting will be removed in future releases
