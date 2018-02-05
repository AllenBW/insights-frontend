'use strict';

const componentsModule = require('../../');

/**
 * @ngInject
 */
function vulnerabilitiesCveViewCtrl($scope,
                                     $stateParams,
                                     InsightsConfig,
                                     Utils,
                                     Vulnerability) {

    $scope.cve_id = $stateParams.cve_id;
    $scope.checkboxes = new Utils.Checkboxes('system_id');
    $scope.config = InsightsConfig;

    function initPageHeader () {
        const public_date = `Public Date: ${$scope.cve.public_date}`;
        const package_count = $scope.cve.packages.length === 1 ? '1 Package' :
                              `${$scope.cve.packages.length} Packages`;
        const rhsa_count = $scope.cve.rhsa_count === 1 ? '1 RHSA' :
                              `${$scope.cve.rhsa_count} RHSAs`;

        $scope.pageHeaderSubtitle = [
                public_date,
                package_count,
                rhsa_count];
    }

    function getData () {
        Vulnerability.getCVE($scope.cve_id).then((cve) => {
            $scope.cve = cve;
            initPageHeader();
            $scope.totalSystems = cve.systems_affected;
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
