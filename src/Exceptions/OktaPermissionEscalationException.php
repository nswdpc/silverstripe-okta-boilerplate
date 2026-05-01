<?php

declare(strict_types=1);

namespace NSWDPC\Authentication\Okta;

use SilverStripe\ORM\ValidationException;

/**
 * An {@link \Exception} thrown when an Okta group is written with permissions
 */
class OktaPermissionEscalationException extends ValidationException
{
}
