'use strict';

const componentsModule = require('../../');

/**
 * @ngInject
 */
function vulnerabilitiesRhsaViewCtrl($scope,
                                     $stateParams,
                                     Utils,
                                     Vulnerability) {

    $scope.rhsa_id = $stateParams.rhsa_id;
    $scope.checkboxes = new Utils.Checkboxes('system_id');

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

componentsModule.controller('vulnerabilitiesRhsaViewCtrl',
  vulnerabilitiesRhsaViewCtrl);
