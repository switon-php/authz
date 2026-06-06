<?php

declare(strict_types=1);

namespace Switon\Authorizing\Tests\Unit;

use ArrayObject;
use Switon\Authorizing\Permissions;
use Switon\Authorizing\Tests\TestCase;

class PermissionFlattenerTest extends TestCase
{
    public function testFlattenBuildsStableItemsFromScan(): void
    {
        $permissions = new Permissions();

        $items = $permissions->flatten([
            'content' => [
                'class' => 'App\\ContentController',
                'actions' => [
                    'index' => 'indexAction',
                    'publish' => 'publishAction',
                ],
                'permissions' => [
                    '*' => [
                        'method' => '*',
                        'roles' => ['editor'],
                        'assignable' => true,
                        'assignable_explicit' => false,
                    ],
                    'publish' => [
                        'method' => 'POST',
                        'roles' => ['editor'],
                        'assignable' => true,
                        'assignable_explicit' => false,
                    ],
                ],
            ],
        ]);

        $this->assertSame([
            [
                'permission_code' => 'content::*',
                'handler_id' => 'content',
                'suffix' => '*',
                'class' => 'App\\ContentController',
                'action_method' => '*',
                'method' => '*',
                'roles' => ['editor'],
                'assignable' => true,
                'assignable_explicit' => false,
                'inherited' => false,
            ],
            [
                'permission_code' => 'content::index',
                'handler_id' => 'content',
                'suffix' => 'index',
                'class' => 'App\\ContentController',
                'action_method' => 'indexAction',
                'method' => '*',
                'roles' => ['editor'],
                'assignable' => false,
                'assignable_explicit' => false,
                'inherited' => true,
            ],
            [
                'permission_code' => 'content::publish',
                'handler_id' => 'content',
                'suffix' => 'publish',
                'class' => 'App\\ContentController',
                'action_method' => 'publishAction',
                'method' => 'POST',
                'roles' => ['editor'],
                'assignable' => true,
                'assignable_explicit' => false,
                'inherited' => false,
            ],
        ], $items);
    }

    public function testFlattenIgnoresMalformedCatalogEntries(): void
    {
        $permissions = new Permissions();

        $items = $permissions->flatten([
            'bad_scalar' => 'not-an-array',
            'bad_missing_permissions' => [
                'class' => 'App\\OrphanController',
            ],
            'ok' => [
                'class' => 'App\\OkController',
                'permissions' => [
                    '*' => [
                        'method' => '*',
                        'roles' => [],
                        'assignable' => true,
                        'assignable_explicit' => false,
                    ],
                ],
            ],
        ]);

        $this->assertCount(1, $items);
        $this->assertSame('ok::*', $items[0]['permission_code']);
    }

    public function testFlattenSkipsWildcardInheritanceWhenPermissionsContainerIsNotPhpArray(): void
    {
        $permissions = new Permissions();

        $items = $permissions->flatten([
            'ctrl' => [
                'class' => 'App\\CtrlController',
                'actions' => ['a' => 'aAction'],
                'permissions' => new ArrayObject([
                    '*' => [
                        'method' => '*',
                        'roles' => [],
                        'reference' => null,
                        'assignable' => true,
                        'assignable_explicit' => false,
                    ],
                ]),
            ],
        ]);

        $this->assertSame([], $items);
    }
}
