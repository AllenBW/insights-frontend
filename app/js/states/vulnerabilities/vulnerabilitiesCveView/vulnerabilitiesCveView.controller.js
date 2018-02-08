'use strict';

const statesModule = require('../../');

/**
 * @ngInject
 */
function vulnerabilitiesCveViewCtrl($filter,
                                    $location,
                                    $scope,
                                    $stateParams,
                                    $state,
                                    InsightsConfig,
                                    Utils,
                                    Vulnerability,
                                    BreadcrumbsService,
                                    InventoryService,
                                    SystemModalTabs) {

    const breadcrumbs = BreadcrumbsService;
    breadcrumbs.init($stateParams);

    $scope.cve_id = $stateParams.cve_id;
    $scope.tabs = SystemModalTabs;
    $scope.showSystem = InventoryService.showSystemModal;
    $scope.config = InsightsConfig;

    $scope.sorter = new Utils.Sorter(
        {
            predicate: $location.search().sort_by || 'toString',
            reverse: $location.search().reverse || false
        },
        order);

    function initPageHeader () {
        const public_date = `Public Date: ${$scope.cve.public_date}`;
        const package_count = $scope.cve.packages.length === 1 ? '1 Package' :
                              `${$scope.cve.packages.length} Packages`;

        $scope.pageHeaderSubtitle = [];
        $scope.pageHeaderSubtitle.push(public_date);
        $scope.pageHeaderSubtitle.push(package_count);

        if ($scope.cve.iava) {
            $scope.pageHeaderSubtitle.push(`IAVA: ${$scope.cve.iava}`);
        }

        if ($scope.cve.cwe) {
            $scope.pageHeaderSubtitle.push(`CWE: ${$scope.cve.cwe}`);
        }
    }

    function getData () {
        Vulnerability.getCVE($scope.cve_id).then((cve) => {
            $scope.cve = cve;
            breadcrumbs.add({
                label: cve.id,
                state: $state.current.name,
                param: {
                    cve_id: $scope.cve_id
                }
            });

            $scope.affectedSystems = cve.systems;
            initPageHeader();
        });
    }

    function order () {
        $location.search('sort_by', $scope.sorter.predicate);
        $location.search('reverse', $scope.sorter.reverse);

        // TODO: use this once api is available
        // getData();

        $scope.affectedSystems = $filter('orderBy')(
            $scope.affectedSystems,
            [($scope.sorter.reverse ?
                '-' + $scope.sorter.predicate :
                $scope.sorter.predicate)]);
    }

    $scope.search = function (model) {
        if (!model || model === '') {
            $scope.affectedSystems = $scope.cve.systems;
        } else {
            $scope.affectedSystems = $filter('filter')(
              $scope.cve.systems, model);
        }
    };

    getData();
}

statesModule.controller('vulnerabilitiesCveViewCtrl',
  vulnerabilitiesCveViewCtrl);
