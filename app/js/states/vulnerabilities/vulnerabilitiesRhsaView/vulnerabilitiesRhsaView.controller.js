'use strict';

const statesModule = require('../../');

/**
 * @ngInject
 */
function vulnerabilitiesRhsaViewCtrl($filter,
                                     $location,
                                     $scope,
                                     $stateParams,
                                     $state,
                                     InsightsConfig,
                                     Utils,
                                     InventoryService,
                                     Vulnerability,
                                     SystemModalTabs,
                                     BreadcrumbsService) {

    const breadcrumbs = BreadcrumbsService;
    breadcrumbs.init($stateParams);

    $scope.rhsa_id = $stateParams.rhsa_id;
    $scope.config = InsightsConfig;
    $scope.showSystem = InventoryService.showSystemModal;
    $scope.tabs = SystemModalTabs;

    $scope.sorter = new Utils.Sorter(
        {
            predicate: $location.search().sort_by || 'toString',
            reverse: $location.search().reverse || false
        },
        order);

    function initPageHeader () {
        const release_date = `Release Date: ${$scope.rhsa.issued}`;
        const package_count = $scope.rhsa.packages.length === 1 ? '1 Package' :
                              `${$scope.rhsa.packages.length} Packages`;
        const cve_count = $scope.rhsa.cve_count === 1 ? '1 CVE' :
                              `${$scope.rhsa.cve_count} CVEs`;

        $scope.pageHeaderSubtitle = [
                release_date,
                package_count,
                cve_count];
    }

    function getData () {

        // TODO: enable once API is available
        // let params = {};
        // params.sort_by = $scope.sorter.predicate;
        // params.sort_dir = $scope.sorter.getSortDirection();

        Vulnerability.getRHSA($scope.rhsa_id).then((rhsa) => {
            $scope.rhsa = rhsa;
            breadcrumbs.add({
                label: rhsa.id,
                state: $state.current.name,
                param: {
                    rhsa_id: $scope.rhsa_id
                }
            });
            initPageHeader();
            $scope.affectedSystems = rhsa.systems;
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

    getData();

    $scope.search = function (model) {
        if (!model || model === '') {
            $scope.affectedSystems = $scope.rhsa.systems;
        } else {
            $scope.affectedSystems = $filter('filter')(
              $scope.rhsa.systems, model);
        }
    };
}

statesModule.controller('vulnerabilitiesRhsaViewCtrl',
  vulnerabilitiesRhsaViewCtrl);
