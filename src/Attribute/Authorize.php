<?php

declare(strict_types=1);

namespace Switon\Authorizing\Attribute;

use Attribute;
use Switon\Core\Exception\InvalidArgumentException;

use function array_values;
use function count;
use function in_array;
use function is_string;
use function str_starts_with;
use function substr;

/**
 * Declares required roles for a controller class or action method.
 *
 * Guidance: Method-level attribute overrides class-level; empty attribute roles continue to permission
 * lookup only for authenticated users (non-empty <code>IdentityInterface::getRoles()</code>); named
 * <code>assignable</code> affects scanned permission metadata only.
 *
 * Road-signs:
 * - read by Authorization::getAuthorize()
 * - enforced in RequestAuthorizing listener
 * - empty attribute roles + unauthenticated user → deny
 * - empty attribute roles + authenticated user → permission lookup
 * - built-in semantics SUPERUSER / AUTHENTICATED / ANONYMOUS (AUTHENTICATED/ANONYMOUS are identity-state markers)
 *
 * @see \Switon\Authorizing\AuthorizationInterface
 * @see \Switon\Authorizing\Authorization::getAuthorize()
 * @see \Switon\Authorizing\Authorization::can()
 * @see \Switon\Http\Event\RequestAuthorizing
 * @see \Switon\Http\Exception\UnauthorizedException
 * @see \Switon\Http\Exception\ForbiddenException
 */
#[Attribute(Attribute::TARGET_CLASS | Attribute::TARGET_METHOD)]
class Authorize
{
    /**
     * Privileged bypass role key; runtime grants when the identity role list contains this string.
     */
    public const string SUPERUSER = 'superuser';

    /**
     * Identity-state marker: attribute step grants for any non-empty <code>IdentityInterface::getRoles()</code>.
     */
    public const string AUTHENTICATED = 'authenticated';

    /**
     * Identity-state marker: grants access to unauthenticated users; skipped during permission lookup.
     */
    public const string ANONYMOUS = 'anonymous';

    /** @var array<string> Required roles (built-in or custom). */
    protected array $roles = [];

    /** Permission reference such as <code>@edit</code> or <code>@admin.todo.edit</code>. */
    protected ?string $reference = null;

    /** Explicit override for scanned <code>assignable</code>; <code>null</code> keeps the default derivation. */
    protected ?bool $assignable = null;

    /**
     * Gets the required roles for access.
     *
     * @return array<string>
     */
    public function getRoles(): array
    {
        return $this->roles;
    }

    /**
     * Gets the permission reference declared with a leading <code>@</code>.
     */
    public function getReference(): ?string
    {
        return $this->reference;
    }

    /**
     * Final <code>assignable</code> for permission scan: <code>ANONYMOUS</code> / <code>AUTHENTICATED</code> force
     * <code>false</code>; otherwise explicit <code>assignable</code> constructor arg or default <code>true</code>.
     */
    public function isAssignable(): bool
    {
        foreach ($this->roles as $role) {
            if ($role === self::ANONYMOUS || $role === self::AUTHENTICATED) {
                return false;
            }
        }

        return $this->assignable ?? true;
    }

    /**
     * Whether the constructor passed an explicit <code>assignable</code> argument (scan/UI metadata).
     */
    public function hasExplicitAssignable(): bool
    {
        return $this->assignable !== null;
    }

    /**
     * Creates a new Authorize attribute instance.
     *
     * @param string|array<string> $roles Required role, permission alias (<code>@edit</code>), or role list
     *                                    (arrays are role-only; empty role list means no attribute grant)
     * @param ?bool $assignable Explicit override for scanned <code>assignable</code>; <code>null</code> keeps the
     *                          default derivation
     *
     * @throws \Switon\Core\Exception\InvalidArgumentException If identity-state roles are combined with other roles,
     *                                                         or an alias is passed inside a role array
     */
    public function __construct(string|array $roles = [], ?bool $assignable = null)
    {
        if (is_string($roles)) {
            if (str_starts_with($roles, '@')) {
                $reference = substr($roles, 1);
                if ($reference === '') {
                    InvalidArgumentException::raise('Authorize permission reference must not be empty.');
                }

                $this->reference = $reference;
            } else {
                $this->roles[] = $roles;
            }
        } else {
            $items = array_values($roles);
            foreach ($items as $item) {
                if (str_starts_with($item, '@')) {
                    InvalidArgumentException::raise(
                        'Authorize permission reference must be passed as a single string, not inside a role array.'
                    );
                }

                $this->roles[] = $item;
            }
        }

        $this->assignable = $assignable;
        $this->assertIdentityStateRolesAreStandalone($this->roles);
    }

    /**
     * @param string[] $roles
     */
    protected function assertIdentityStateRolesAreStandalone(array $roles): void
    {
        if ($roles === []) {
            return;
        }

        if (in_array(self::ANONYMOUS, $roles, true) && (count($roles) !== 1 || $roles[0] !== self::ANONYMOUS)) {
            InvalidArgumentException::raise(self::ANONYMOUS . ' must be used as a standalone role in #[Authorize].');
        }

        if (in_array(self::AUTHENTICATED, $roles, true) && (count($roles) !== 1 || $roles[0] !== self::AUTHENTICATED)) {
            InvalidArgumentException::raise(self::AUTHENTICATED . ' must be used as a standalone role in #[Authorize].');
        }
    }
}
