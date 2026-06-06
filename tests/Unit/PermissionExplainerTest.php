<?php

declare(strict_types=1);

namespace Switon\Authorizing\Tests\Unit;

use Switon\Authorizing\Permissions;
use Switon\Authorizing\Tests\TestCase;

class PermissionExplainerTest extends TestCase
{
    public function testExplainReturnsGroupedSourcesForEffectiveDirectInheritedAndAssignedPermissions(): void
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
        ];

        $this->assertSame([
            'content' => [
                '*' => 'direct-explicit',
                'index' => 'inherited-explicit',
                'publish' => 'direct-explicit',
            ],
            'report' => [
                'view' => 'direct-assigned',
            ],
        ], $permissions->explain($scanResult, 'editor', ['report::view']));
    }

    public function testExplainUsesWildcardGrantForInheritedActions(): void
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

        $this->assertSame([
            'content' => [
                '*' => 'direct-assigned',
                'index' => 'inherited-assigned',
            ],
        ], $permissions->explain($scanResult, 'viewer', ['content::*']));
    }

    public function testExplainSkipsPermissionRowsWithEmptySuffixKey(): void
    {
        $permissions = new Permissions();

        $scanResult = [
            'edge' => [
                'class' => 'App\\EdgeController',
                'actions' => [],
                'permissions' => [
                    '' => [
                        'method' => 'edgeAction',
                        'roles' => [],
                        'reference' => null,
                        'assignable' => true,
                        'assignable_explicit' => false,
                    ],
                    'view' => [
                        'method' => 'viewAction',
                        'roles' => ['editor'],
                        'reference' => null,
                        'assignable' => true,
                        'assignable_explicit' => false,
                    ],
                ],
            ],
        ];

        $this->assertSame([
            'edge' => [
                'view' => 'direct-explicit',
            ],
        ], $permissions->explain($scanResult, 'editor', []));
    }

    public function testExplainMarksReferencedPermissions(): void
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
                        'reference' => 'edit',
                        'assignable' => true,
                        'assignable_explicit' => false,
                    ],
                ],
            ],
        ];

        $this->assertSame([
            'notice' => [
                'create' => 'direct-assigned',
                'delete' => 'direct-referenced',
                'edit' => 'direct-referenced',
            ],
        ], $permissions->explain($scanResult, 'editor', ['notice::create']));
    }
}
