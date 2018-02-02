'use strict';

const componentsModule = require('../../');

/**
 * @ngInject
 */
function vulnerabilitiesRhsaViewCtrl($scope, $stateParams, Vulnerability) {

    $scope.rhsa_id = $stateParams.rhsa_id;

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
}

componentsModule.controller('vulnerabilitiesRhsaViewCtrl',
  vulnerabilitiesRhsaViewCtrl);
