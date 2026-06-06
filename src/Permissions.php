<?php

declare(strict_types=1);

namespace Switon\Authorizing;

use ReflectionAttribute;
use ReflectionClass;
use ReflectionMethod;
use Switon\Core\Attribute\Autowired;
use Switon\Core\Exception\RuntimeException;
use Switon\Routing\Attribute\MappingInterface;
use Switon\Routing\ControllerScannerInterface;
use Switon\Routing\HandlerIdInterface;

use function array_key_exists;
use function array_reverse;
use function explode;
use function in_array;
use function is_array;
use function ksort;
use function sort;
use function str_contains;

/**
 * Default unified permission utilities.
 *
 * Guidance: Use this as the single permission entrypoint in app code; keep persistence joins (<code>permission_id</code>, labels, role-binding tables) outside this class.
 *
 * @phpstan-import-type Catalog from PermissionsInterface
 * @phpstan-import-type FlattenRow from PermissionsInterface
 * @phpstan-import-type SourceMap from PermissionsInterface
 *
 * @see \Switon\Authorizing\PermissionsInterface
 * @see \Switon\Authorizing\Attribute\Authorize
 * @see \Switon\Routing\ControllerScannerInterface
 * @see \Switon\Routing\HandlerIdInterface
 * @see \Switon\Routing\Attribute\MappingInterface
 */
class Permissions implements PermissionsInterface
{
    #[Autowired] protected ControllerScannerInterface $controllerScanner;
    #[Autowired] protected HandlerIdInterface $handlerId;

    /**
     * @phpstan-return Catalog
     */
    public function scanCatalog(): array
    {
        $byPrefix = [];
        foreach ($this->controllerScanner->getControllers() as $controller) {
            $rClass = new ReflectionClass($controller);
            $controllerAuthorize = ($rClass->getAttributes(Attribute\Authorize::class, ReflectionAttribute::IS_INSTANCEOF)[0] ?? null)?->newInstance();

            if ($controllerAuthorize !== null) {
                $fullHandlerId = $this->handlerId->getId($controller, '*');
                $parts = explode('::', $fullHandlerId, 2);
                $controllerId = $parts[0];
                $handlerSuffix = $parts[1] ?? '';

                if (!isset($byPrefix[$controllerId])) {
                    $byPrefix[$controllerId] = [
                        'class' => $controller,
                        'actions' => [],
                        'permissions' => [],
                    ];
                }

                $byPrefix[$controllerId]['permissions'][$handlerSuffix] = [
                    'method' => '*',
                    'roles' => $controllerAuthorize->getRoles(),
                    'reference' => $controllerAuthorize->getReference(),
                    'assignable' => $controllerAuthorize->isAssignable(),
                    'assignable_explicit' => $controllerAuthorize->hasExplicitAssignable(),
                ];
            }

            foreach ($rClass->getMethods(ReflectionMethod::IS_PUBLIC) as $rMethod) {
                if ($rMethod->getAttributes(MappingInterface::class, ReflectionAttribute::IS_INSTANCEOF) === []) {
                    continue;
                }

                $authorize = ($rMethod->getAttributes(Attribute\Authorize::class, ReflectionAttribute::IS_INSTANCEOF)[0] ?? null)?->newInstance();
                $fullHandlerId = $this->handlerId->getId($controller, $rMethod->getName());
                $parts = explode('::', $fullHandlerId, 2);
                $controllerId = $parts[0];
                $handlerSuffix = $parts[1] ?? '';

                if (!isset($byPrefix[$controllerId])) {
                    $byPrefix[$controllerId] = [
                        'class' => $controller,
                        'actions' => [],
                        'permissions' => [],
                    ];
                }

                if ($authorize === null && $controllerAuthorize !== null) {
                    $byPrefix[$controllerId]['actions'][$handlerSuffix] = $rMethod->getName();
                    continue;
                }

                $roles = $authorize?->getRoles() ?? [];
                $reference = $authorize?->getReference();
                $assignable = $authorize !== null ? $authorize->isAssignable() : $controllerAuthorize === null;
                $assignableExplicit = $authorize !== null && $authorize->hasExplicitAssignable();

                if ($authorize !== null && $roles === [] && $reference !== null && $controllerAuthorize !== null) {
                    $roles = $controllerAuthorize->getRoles();
                    if (!$assignableExplicit) {
                        $assignable = $controllerAuthorize->isAssignable();
                    }
                }

                $byPrefix[$controllerId]['permissions'][$handlerSuffix] = [
                    'method' => $rMethod->getName(),
                    'roles' => $roles,
                    'reference' => $reference,
                    'assignable' => $assignable,
                    'assignable_explicit' => $assignableExplicit,
                ];
                $byPrefix[$controllerId]['actions'][$handlerSuffix] = $rMethod->getName();
            }
        }

        foreach ($byPrefix as &$entry) {
            ksort($entry['actions']);
            ksort($entry['permissions']);
        }
        unset($entry);
        ksort($byPrefix);

        return $byPrefix;
    }

    /**
     * @phpstan-param Catalog $catalog
     *
     * @phpstan-return list<FlattenRow>
     */
    public function flatten(array $catalog): array
    {
        $rows = $this->buildNormalizedRows($catalog);

        $items = [];
        foreach ($rows as $permissionCode => $row) {
            $parts = explode('::', $permissionCode, 2);
            $handlerId = (string)($parts[0] ?? '');
            $suffix = (string)($parts[1] ?? '');
            $entry = $catalog[$handlerId] ?? null;

            $actions = is_array($entry) ? ($entry['actions'] ?? null) : null;
            $permissions = is_array($entry) ? ($entry['permissions'] ?? null) : null;

            $actionMethod = '*';
            if ($suffix !== '*') {
                $actionMethod = is_array($actions) ? (string)($actions[$suffix] ?? $suffix) : $suffix;
            }

            $httpMethod = '*';
            if (is_array($permissions)) {
                if (isset($permissions[$suffix]['method'])) {
                    $httpMethod = (string)$permissions[$suffix]['method'];
                } elseif (isset($permissions['*']['method'])) {
                    $httpMethod = (string)$permissions['*']['method'];
                }
            }

            $items[] = [
                'permission_code' => $permissionCode,
                'handler_id' => $handlerId,
                'suffix' => $suffix,
                'class' => (string)(is_array($entry) ? ($entry['class'] ?? '') : ''),
                'action_method' => $actionMethod,
                'method' => $httpMethod,
                'roles' => $row['roles'],
                'assignable' => $row['assignable'],
                'assignable_explicit' => $row['assignable_explicit'],
                'inherited' => $row['inherited'],
            ];
        }

        return $items;
    }

    /**
     * @phpstan-param Catalog $catalog
     * @phpstan-param list<string> $grantedPermissions
     *
     * @phpstan-return list<string>
     */
    public function expand(array $catalog, string $role, array $grantedPermissions): array
    {
        $rows = $this->buildNormalizedRows($catalog);
        $granted = [];
        foreach ($grantedPermissions as $code) {
            $granted[$code] = true;
        }

        $result = [];
        foreach ($rows as $permissionCode => $row) {
            $parts = explode('::', $permissionCode, 2);
            if (($parts[1] ?? '') === '*' || ($parts[1] ?? '') === '') {
                continue;
            }

            $effectiveCode = $permissionCode;
            if ($row['inherited'] && array_key_exists($parts[0] . '::*', $rows)) {
                $effectiveCode = $parts[0] . '::*';
            }
            $effective = $rows[$effectiveCode] ?? null;
            if ($effective === null) {
                continue;
            }

            if (in_array($role, $effective['roles'], true)) {
                $result[] = $permissionCode;
                continue;
            }
            if ($effective['assignable'] && isset($granted[$effectiveCode])) {
                $result[] = $permissionCode;
            }
        }

        $result = $this->expandReferencedPermissions($rows, $result);
        sort($result);
        return $result;
    }

    /**
     * @phpstan-param Catalog $catalog
     * @phpstan-param list<string> $grantedPermissions
     *
     * @phpstan-return SourceMap
     */
    public function explain(array $catalog, string $role, array $grantedPermissions): array
    {
        $rows = $this->buildNormalizedRows($catalog);
        $granted = [];
        foreach ($grantedPermissions as $code) {
            $granted[$code] = true;
        }

        $sources = [];
        foreach ($rows as $permissionCode => $row) {
            $parts = explode('::', $permissionCode, 2);
            $handlerId = (string)($parts[0] ?? '');
            $suffix = (string)($parts[1] ?? '');
            if ($suffix === '') {
                continue;
            }

            $effectiveCode = $permissionCode;
            if ($row['inherited'] && array_key_exists($handlerId . '::*', $rows)) {
                $effectiveCode = $handlerId . '::*';
            }
            $effective = $rows[$effectiveCode] ?? null;
            if ($effective === null) {
                continue;
            }

            $prefix = $row['inherited'] ? 'inherited' : 'direct';
            if (in_array($role, $effective['roles'], true)) {
                $sources[$handlerId][$suffix] = $prefix . '-explicit';
                continue;
            }
            if ($effective['assignable'] && isset($granted[$effectiveCode])) {
                $sources[$handlerId][$suffix] = $prefix . '-assigned';
            }
        }

        foreach ($this->expandReferencedPermissions($rows, $this->flattenSourceCodes($sources)) as $permissionCode) {
            $parts = explode('::', $permissionCode, 2);
            $handlerId = (string)($parts[0] ?? '');
            $suffix = (string)($parts[1] ?? '');
            if ($suffix === '' || isset($sources[$handlerId][$suffix])) {
                continue;
            }

            $row = $rows[$permissionCode] ?? null;
            if ($row === null) {
                continue;
            }

            $sources[$handlerId][$suffix] = ($row['inherited'] ? 'inherited' : 'direct') . '-referenced';
        }

        foreach ($sources as &$group) {
            ksort($group);
        }
        unset($group);
        ksort($sources);

        return $sources;
    }

    /**
     * @param array<string, array{
     *   actions?: array<string, string>,
     *   permissions?: array<string, array{roles?: string[], reference?: ?string, assignable?: bool, assignable_explicit?: bool}>
     * }> $catalog
     *
     * @return array<string, array{roles: string[], reference: ?string, assignable: bool, assignable_explicit: bool, inherited: bool}>
     */
    private function buildNormalizedRows(array $catalog): array
    {
        $rows = [];
        foreach ($catalog as $controllerId => $entry) {
            if (!is_array($entry) || !isset($entry['permissions']) || !is_array($entry['permissions'])) {
                continue;
            }

            foreach ($entry['permissions'] as $suffix => $definition) {
                $permissionCode = $controllerId . '::' . $suffix;
                $rows[$permissionCode] = [
                    'roles' => $definition['roles'] ?? [],
                    'reference' => $this->normalizeReference($controllerId, $definition['reference'] ?? null),
                    'assignable' => (bool)($definition['assignable'] ?? false),
                    'assignable_explicit' => (bool)($definition['assignable_explicit'] ?? false),
                    'inherited' => false,
                ];
            }
        }

        foreach ($catalog as $controllerId => $entry) {
            if (!is_array($entry) || !isset($entry['permissions']['*'], $entry['actions']) || !is_array($entry['actions'])) {
                continue;
            }

            $wildcardPermission = $controllerId . '::*';
            $wildcard = $rows[$wildcardPermission] ?? null;
            if ($wildcard === null) {
                continue;
            }

            foreach ($entry['actions'] as $suffix => $_methodName) {
                $permissionCode = $controllerId . '::' . $suffix;
                if (isset($rows[$permissionCode])) {
                    continue;
                }

                $rows[$permissionCode] = [
                    'roles' => $wildcard['roles'],
                    'reference' => null,
                    'assignable' => false,
                    'assignable_explicit' => false,
                    'inherited' => true,
                ];
            }
        }

        $this->assertReferenceTargetsExist($rows);
        $this->assertNoReferenceCycles($rows);

        ksort($rows);
        return $rows;
    }

    /**
     * Normalizes one scanned permission reference into full <code>handler::suffix</code> form.
     */
    private function normalizeReference(string $controllerId, mixed $reference): ?string
    {
        if (!is_string($reference) || $reference === '') {
            return null;
        }

        if (str_contains($reference, '::')) {
            return $reference;
        }

        if (str_contains($reference, '.')) {
            $parts = explode('.', $reference);
            $suffix = array_pop($parts);
            $prefix = implode('.', $parts);
            return $prefix . '::' . $suffix;
        }

        return $controllerId . '::' . $reference;
    }

    /**
     * @param array<string, array{reference: ?string}> $rows
     */
    private function assertReferenceTargetsExist(array $rows): void
    {
        foreach ($rows as $permissionCode => $row) {
            $reference = $row['reference'];
            if ($reference === null || isset($rows[$reference])) {
                continue;
            }

            RuntimeException::raise(
                'Permission reference "{reference}" declared by "{permission}" was not found in the scanned catalog.',
                ['reference' => $reference, 'permission' => $permissionCode]
            );
        }
    }

    /**
     * @param array<string, array{reference: ?string}> $rows
     */
    private function assertNoReferenceCycles(array $rows): void
    {
        $visited = [];
        $visiting = [];
        /** @var list<string> $path */
        $path = [];
        $walk = static function (string $permissionCode) use (&$walk, &$visited, &$visiting, &$path, $rows): void {
            if (isset($visited[$permissionCode])) {
                return;
            }

            if (isset($visiting[$permissionCode])) {
                $cycle = [];
                foreach (array_reverse($path) as $node) {
                    $cycle[] = $node;
                    if ($node === $permissionCode) {
                        break;
                    }
                }

                $cycle = array_reverse($cycle);
                $cycle[] = $permissionCode;
                RuntimeException::raise('Permission references contain a cycle: {cycle}', [
                    'cycle' => implode(' -> ', $cycle),
                ]);
            }

            $visiting[$permissionCode] = true;
            $path[] = $permissionCode;
            $reference = $rows[$permissionCode]['reference'];
            if ($reference !== null) {
                $walk($reference);
            }
            array_pop($path);
            unset($visiting[$permissionCode]);
            $visited[$permissionCode] = true;
        };

        foreach (array_keys($rows) as $permissionCode) {
            $walk($permissionCode);
        }
    }

    /**
     * @param array<string, array{reference: ?string}> $rows
     * @param array<int, string> $codes
     *
     * @return array<int, string>
     */
    private function expandReferencedPermissions(array $rows, array $codes): array
    {
        $granted = [];
        foreach ($codes as $code) {
            $granted[$code] = true;
        }

        $reverse = [];
        foreach ($rows as $permissionCode => $row) {
            $reference = $row['reference'];
            if ($reference !== null) {
                $reverse[$reference][] = $permissionCode;
            }
        }

        $queue = array_keys($granted);
        while (($current = array_shift($queue)) !== null) {
            foreach ($reverse[$current] ?? [] as $derivedCode) {
                if (isset($granted[$derivedCode])) {
                    continue;
                }

                $granted[$derivedCode] = true;
                $queue[] = $derivedCode;
            }
        }

        return array_keys($granted);
    }

    /**
     * @param array<string, array<string, string>> $sources
     *
     * @return array<int, string>
     */
    private function flattenSourceCodes(array $sources): array
    {
        $codes = [];
        foreach ($sources as $handlerId => $group) {
            foreach (array_keys($group) as $suffix) {
                $codes[] = $handlerId . '::' . $suffix;
            }
        }

        return $codes;
    }
}
