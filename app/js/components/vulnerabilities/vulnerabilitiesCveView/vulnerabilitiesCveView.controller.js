'use strict';

const componentsModule = require('../../');

/**
 * @ngInject
 */
function vulnerabilitiesCveViewCtrl($scope,
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
    $scope.checkboxes = new Utils.Checkboxes('system_id');
    $scope.config = InsightsConfig;

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
            breadcrumbs.setCrumb({
                label: cve.id,
                state: $state.current.name,
                param: {
                    cve_id: $scope.cve_id
                }
            }, 1);
            $scope.totalSystems = cve.systems_affected;
            initPageHeader();
        });
    }

    getData();

    $scope.$watchCollection('checkboxes.items', updateCheckboxes);
    function updateCheckboxes () {
        $scope.checkboxes.update($scope.ruleSystems);

        if ($scope.checkboxes.totalChecked > 0) {
            $scope.noSystemsSelected = false;
        }

        $scope.allSelected = ($scope.checkboxes.totalChecked > 0 &&
                             !$scope.checkboxes.indeterminate);

        if (!$scope.allSelected) {
            $scope.reallyAllSelected = false;
        }
    }
}

componentsModule.controller('vulnerabilitiesCveViewCtrl',
  vulnerabilitiesCveViewCtrl);
