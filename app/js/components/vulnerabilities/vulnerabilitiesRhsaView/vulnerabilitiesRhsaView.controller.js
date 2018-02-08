'use strict';

const componentsModule = require('../../');

/**
 * @ngInject
 */
function vulnerabilitiesRhsaViewCtrl($scope,
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
            $scope.totalSystems = rhsa.systems_affected;
        });
    }

    getData();

    $scope.search = function (model) {
        //TODO: table search
        console.log(model);
    };
}

componentsModule.controller('vulnerabilitiesRhsaViewCtrl',
  vulnerabilitiesRhsaViewCtrl);
