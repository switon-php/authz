<?php

declare(strict_types=1);

namespace Switon\Authorizing\Event;

use JsonSerializable;
use Switon\Eventing\Attribute\EventLevel;
use Switon\Eventing\Severity;

/**
 * Event emitted when authorization enforcement grants access.
 *
 * Log category: <code>switon.authorizing.authorization.granted</code>
 *
 * @see \Switon\Authorizing\Authorization::authorize()
 * @see \Switon\Authorizing\Event\AuthorizationDenied
 */
#[EventLevel(Severity::DEBUG)]
class AuthorizationGranted implements JsonSerializable
{
    /**
     * @param string $operation Permission code (for example <code>admin::create-user</code> or <code>rbac.role::index</code>) or handler reference
     *                          (<code>FQCN::method</code>)
     * @param array<string> $roles Roles used for the decision
     */
    public function __construct(
        public string $operation,
        public array  $roles,
    ) {
    }

    /** @return array<string, mixed> */
    public function jsonSerialize(): array
    {
        return [
            'operation' => $this->operation,
            'roles' => $this->roles,
        ];
    }
}
