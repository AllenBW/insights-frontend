/*global angular */
'use strict';

describe('MaintenanceController', function () {
    let scope;
    let service;
    let api;
    let q;
    let params;

    function mockAsPromised (data) {
        return function () {
            return q.when(data);
        };
    }

    function initCtrl () {
        let ctrl;
        angular.mock.inject(function ($controller, MaintenanceService) {
            service = MaintenanceService;
            ctrl = $controller('MaintenanceCtrl', {
                $scope: scope
            });
        });

        return ctrl;
    }

    beforeEach(function () {
        // mocks
        angular.mock.module('insights', function ($provide) {
            $provide.factory('Report', function ($q) {
                q = $q;
                return {
                    getAllReports: mockAsPromised([])
                };
            });

            $provide.factory('User', function () {
                return {
                    init: mockAsPromised({
                        account_number: '540155',
                        is_internal: true
                    }),
                    current: {}
                };
            });

            $provide.factory('Rule', function () {
                const mockRule = {
                    data: {
                        resources: []
                    }
                };
                return {
                    getRulesLatest: mockAsPromised(mockRule)
                };
            });

            $provide.factory('System', function () {
                const mockSystems = {
                    data: {
                        resources: [{
                            account_number: '540155',
                            created_at: '2016-11-10T15:45:22.000Z',
                            display_name: 'rhaiceph1.rhaitest.cee.redhat.com',
                            hostname: null,
                            isCheckingIn: false,
                            last_check_in: '2015-10-30T02:18:56.000Z',
                            product_code: 'osp',
                            remote_branch: null,
                            remote_leaf: null,
                            report_count: 1,
                            role: 'cluster',
                            system_id: 'f442691088614ddba5d756592b5d4b93',
                            system_type_id: 7,
                            toString: 'rhaiceph1.rhaitest.cee.redhat.com',
                            unregistered_at: null,
                            updated_at: '2016-11-10T15:45:22.000Z'
                        }]
                    }
                };
                return {
                    getSystemTypes: mockAsPromised([]),
                    getSystemsLatest: mockAsPromised(mockSystems)
                };
            });

            $provide.factory('$state', function () {
                return {
                    transitionTo: function () {
                        // noop
                    },

                    current: 'app.maintenance',
                    get: function () {
                        return this.current;
                    }
                };
            });

            $provide.factory('$stateParams', function () {
                return {};
            });
        });

        angular.mock.inject(function (Maintenance) {
            Maintenance.getMaintenancePlans = mockAsPromised([]);
        });

        // setup
        angular.mock.inject(function ($rootScope, Maintenance, $stateParams) {
            scope = $rootScope.$new();
            api = Maintenance;
            params = $stateParams;
        });
    });

    it('opens "all" category by default', function () {
        initCtrl();
        scope.$digest();
        scope.category.should.equal('all');
    });

    it('switches to different category', function () {
        initCtrl();
        scope.$digest();
        scope.setCategory('future');
        scope.$digest();
        scope.category.should.equal('future');

        scope.setCategory('past');
        scope.$digest();
        scope.category.should.equal('past');
    });
});
