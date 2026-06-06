<?php

declare(strict_types=1);

namespace Switon\Authorizing\Tests\Unit;

use Switon\Authorizing\Permissions;
use Switon\Core\Exception\RuntimeException;
use Switon\Authorizing\Tests\TestCase;

class PermissionExpansionTest extends TestCase
{
    public function testExpandReturnsConcretePermissionsFromInheritedAndGrantedPermissions(): void
    {
        $permissions = new Permissions();

        $scanResult = [
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
                        'reference' => null,
                        'assignable' => true,
                        'assignable_explicit' => false,
                    ],
                    'publish' => [
                        'method' => 'publishAction',
                        'roles' => ['editor'],
                        'reference' => null,
                        'assignable' => true,
                        'assignable_explicit' => false,
                    ],
                ],
            ],
            'report' => [
                'class' => 'App\\ReportController',
                'actions' => ['view' => 'viewAction'],
                'permissions' => [
                    'view' => [
                        'method' => 'viewAction',
                        'roles' => [],
                        'reference' => null,
                        'assignable' => true,
                        'assignable_explicit' => false,
                    ],
                ],
            ],
            'legacy' => [
                'class' => 'App\\LegacyController',
                'actions' => ['x' => 'xAction'],
                'permissions' => [
                    'x' => [
                        'method' => 'xAction',
                        'roles' => [],
                        'reference' => null,
                        'assignable' => true,
                        'assignable_explicit' => false,
                    ],
                ],
            ],
        ];

        $this->assertSame([
            'content::index',
            'content::publish',
            'legacy::x',
            'report::view',
        ], $permissions->expand($scanResult, 'editor', ['report::view', 'legacy::x']));
    }

    public function testExpandKeepsWildcardGrantInsideInheritedBoundary(): void
    {
        $permissions = new Permissions();

        $scanResult = [
            'content' => [
                'class' => 'App\\ContentController',
                'actions' => [
                    'index' => 'indexAction',
                    'publish' => 'publishAction',
                ],
                'permissions' => [
                    '*' => [
                        'method' => '*',
                        'roles' => [],
                        'reference' => null,
                        'assignable' => true,
                        'assignable_explicit' => false,
                    ],
                    'publish' => [
                        'method' => 'publishAction',
                        'roles' => ['editor'],
                        'reference' => null,
                        'assignable' => true,
                        'assignable_explicit' => false,
                    ],
                ],
            ],
        ];

        $this->assertSame(['content::index'], $permissions->expand($scanResult, 'viewer', ['content::*']));
    }

    public function testExpandKeepsFullHandlerReferenceStringsWhenReferenceContainsDoubleColon(): void
    {
        $permissions = new Permissions();

        $scanResult = [
            'notice' => [
                'class' => 'App\\NoticeController',
                'actions' => [
                    'delete' => 'deleteAction',
                ],
                'permissions' => [
                    'delete' => [
                        'method' => 'deleteAction',
                        'roles' => [],
                        'reference' => 'notice::create',
                        'assignable' => true,
                        'assignable_explicit' => false,
                    ],
                    'create' => [
                        'method' => 'createAction',
                        'roles' => [],
                        'reference' => null,
                        'assignable' => true,
                        'assignable_explicit' => false,
                    ],
                ],
            ],
        ];

        $this->assertSame([
            'notice::create',
            'notice::delete',
        ], $permissions->expand($scanResult, 'editor', ['notice::create']));
    }

    public function testExpandSkipsReAddingPermissionsAlreadyInGrantClosure(): void
    {
        $permissions = new Permissions();

        $scanResult = [
            'notice' => [
                'class' => 'App\\NoticeController',
                'actions' => [
                    'create' => 'createAction',
                    'edit' => 'editAction',
                    'delete' => 'deleteAction',
                ],
                'permissions' => [
                    'create' => [
                        'method' => 'createAction',
                        'roles' => ['editor'],
                        'reference' => null,
                        'assignable' => true,
                        'assignable_explicit' => false,
                    ],
                    'edit' => [
                        'method' => 'editAction',
                        'roles' => ['editor'],
                        'reference' => 'create',
                        'assignable' => true,
                        'assignable_explicit' => false,
                    ],
                    'delete' => [
                        'method' => 'deleteAction',
                        'roles' => ['editor'],
                        'reference' => 'edit',
                        'assignable' => true,
                        'assignable_explicit' => false,
                    ],
                ],
            ],
        ];

        $this->assertSame([
            'notice::create',
            'notice::delete',
            'notice::edit',
        ], $permissions->expand($scanResult, 'editor', []));
    }

    public function testExpandAddsReferencedPermissionWhenTargetPermissionIsGranted(): void
    {
        $permissions = new Permissions();

        $scanResult = [
            'notice' => [
                'class' => 'App\\NoticeController',
                'actions' => [
                    'create' => 'createAction',
                    'delete' => 'deleteAction',
                    'edit' => 'editAction',
                ],
                'permissions' => [
                    'create' => [
                        'method' => 'createAction',
                        'roles' => [],
                        'reference' => null,
                        'assignable' => true,
                        'assignable_explicit' => false,
                    ],
                    'edit' => [
                        'method' => 'editAction',
                        'roles' => [],
                        'reference' => 'create',
                        'assignable' => true,
                        'assignable_explicit' => false,
                    ],
                    'delete' => [
                        'method' => 'deleteAction',
                        'roles' => [],
                        'reference' => 'notice.edit',
                        'assignable' => true,
                        'assignable_explicit' => false,
                    ],
                ],
            ],
        ];

        $this->assertSame([
            'notice::create',
            'notice::delete',
            'notice::edit',
        ], $permissions->expand($scanResult, 'editor', ['notice::create']));
    }

    public function testExpandThrowsWhenPermissionReferenceTargetIsMissing(): void
    {
        $permissions = new Permissions();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Permission reference "notice::missing" declared by "notice::delete" was not found');

        $permissions->expand([
            'notice' => [
                'class' => 'App\\NoticeController',
                'actions' => ['delete' => 'deleteAction'],
                'permissions' => [
                    'delete' => [
                        'method' => 'deleteAction',
                        'roles' => [],
                        'reference' => 'missing',
                        'assignable' => true,
                        'assignable_explicit' => false,
                    ],
                ],
            ],
        ], 'editor', []);
    }

    public function testExpandThrowsWhenPermissionReferencesContainCycle(): void
    {
        $permissions = new Permissions();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Permission references contain a cycle');

        $permissions->expand([
            'notice' => [
                'class' => 'App\\NoticeController',
                'actions' => [
                    'edit' => 'editAction',
                    'delete' => 'deleteAction',
                ],
                'permissions' => [
                    'edit' => [
                        'method' => 'editAction',
                        'roles' => [],
                        'reference' => 'delete',
                        'assignable' => true,
                        'assignable_explicit' => false,
                    ],
                    'delete' => [
                        'method' => 'deleteAction',
                        'roles' => [],
                        'reference' => 'edit',
                        'assignable' => true,
                        'assignable_explicit' => false,
                    ],
                ],
            ],
        ], 'editor', []);
    }

    public function testExpandDoesNotUseGrantedWildcardWhenControllerPermissionIsNotAssignable(): void
    {
        $permissions = new Permissions();

        $scanResult = [
            'content' => [
                'class' => 'App\\ContentController',
                'actions' => [
                    'index' => 'indexAction',
                    'publish' => 'publishAction',
                ],
                'permissions' => [
                    '*' => [
                        'method' => '*',
                        'roles' => [],
                        'reference' => null,
                        'assignable' => false,
                        'assignable_explicit' => true,
                    ],
                ],
            ],
        ];

        $this->assertSame([], $permissions->expand($scanResult, 'viewer', ['content::*']));
    }
}
