<?php

declare(strict_types=1);

namespace Switon\Authorizing;

/**
 * Unified permission utilities for scan-catalog, flatten, expand, and explain.
 *
 * Guidance: This contract stays storage-agnostic; pass granted permissions as <code>controller::action</code> or <code>controller::*</code> codes, not DB ids.
 *
 * Road-signs:
 * - scanCatalog() groups by handler-id prefix
 * - flatten() emits storage-agnostic rows
 * - expand() returns concrete codes only
 * - explain() reports the source of each effective row
 *
 * @phpstan-type PermissionEntry array{method: string, roles: array<string>, reference: ?string, assignable: bool, assignable_explicit: bool}
 * @phpstan-type Catalog array<string, array{class: class-string, actions: array<string, string>, permissions: array<string, PermissionEntry>}>
 * @phpstan-type FlattenRow array{permission_code: string, handler_id: string, suffix: string, class: string, action_method: string, method: string, roles: array<string>, assignable: bool, assignable_explicit: bool, inherited: bool}
 * @phpstan-type SourceMap array<string, array<string, string>>
 *
 * @see \Switon\Authorizing\Attribute\Authorize
 * @see \Switon\Routing\ControllerScannerInterface
 * @see \Switon\Routing\HandlerIdInterface
 * @see \Switon\Routing\Attribute\MappingInterface
 */
interface PermissionsInterface
{
    /**
     * Builds one storage-agnostic permission catalog from controller authorize metadata.
     *
     * @return array<string, array{
     *   class: class-string,
     *   actions: array<string, string>,
     *   permissions: array<string, array{method: string, roles: string[], reference: ?string, assignable: bool, assignable_explicit: bool}>
     * }>
     *
     * Top-level key = handler-id prefix (segment before <code>::</code>).
     * <code>actions</code> contains routable suffixes; <code>permissions</code> is sparse
     * (explicit rows plus <code>*</code> class-level rule).
     *
     * @phpstan-return Catalog
     */
    public function scanCatalog(): array;

    /**
     * Flattens one permission catalog into stable permission rows.
     *
     * @param array<string, array{
     *   class: class-string,
     *   actions: array<string, string>,
     *   permissions: array<string, array{method: string, roles: string[], reference: ?string, assignable: bool, assignable_explicit: bool}>
     * }> $catalog
     *
     * @phpstan-param Catalog $catalog
     *
     * @return array<int, array{
     *   permission_code: string,
     *   handler_id: string,
     *   suffix: string,
     *   class: string,
     *   action_method: string,
     *   method: string,
     *   roles: string[],
     *   assignable: bool,
     *   assignable_explicit: bool,
     *   inherited: bool
     * }>
     *
     * Output rows are storage-agnostic and must not include DB fields such as <code>permission_id</code>.
     *
     * @phpstan-return list<FlattenRow>
     */
    public function flatten(array $catalog): array;

    /**
     * Resolves effective concrete permission codes for one role assignment.
     *
     * @param array<string, array{
     *   class: class-string,
     *   actions: array<string, string>,
     *   permissions: array<string, array{method: string, roles: string[], reference: ?string, assignable: bool, assignable_explicit: bool}>
     * }> $catalog
     * @param string[] $grantedPermissions
     *
     * @phpstan-param Catalog $catalog
     * @phpstan-param list<string> $grantedPermissions
     *
     * @return string[]
     *
     * Returned codes are concrete <code>handler::suffix</code> entries only; wildcard <code>handler::*</code> is not returned.
     *
     * @phpstan-return list<string>
     */
    public function expand(array $catalog, string $role, array $grantedPermissions): array;

    /**
     * Explains why one role gets each effective permission row.
     *
     * @param array<string, array{
     *   class: class-string,
     *   actions: array<string, string>,
     *   permissions: array<string, array{method: string, roles: string[], reference: ?string, assignable: bool, assignable_explicit: bool}>
     * }> $catalog
     * @param string[] $grantedPermissions
     *
     * @phpstan-param Catalog $catalog
     * @phpstan-param list<string> $grantedPermissions
     *
     * @return array<string, array<string, string>>
     *
     * Output shape is <code>handler-id => suffix => source</code>; source values are
     * <code>direct-explicit</code>, <code>direct-assigned</code>, <code>direct-referenced</code>,
     * <code>inherited-explicit</code>, <code>inherited-assigned</code>, and <code>inherited-referenced</code>.
     *
     * @phpstan-return SourceMap
     */
    public function explain(array $catalog, string $role, array $grantedPermissions): array;
}
