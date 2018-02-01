'use strict';

const componentsModule = require('../../');
const findAll = require('lodash/filter');

/**
 * @ngInject
 */
function vulnerabilitiesPackageViewCtrl($scope,
                                  $stateParams,
                                  Vulnerability,
                                  Events) {
    const package_id = $stateParams.package_id;
    let _allRhsas;
    $scope.loading = false;

    $scope.selectRHSA = function (rhsa) {
        $scope.selectedRHSA = rhsa;
    };

    // TODO server side search
    $scope.search = function (model) {
        $scope.rhsas = findAll(_allRhsas, function (rhsa) {
            return rhsa.id.toUpperCase().indexOf(model.toUpperCase()) > -1;
        });
    };

    function getData() {
        $scope.loading = true;
        Vulnerability.getPackage(package_id).then((pkg) => {
            $scope.package_name = pkg.name;
            $scope.rhsas = _allRhsas = pkg.rhsas;
            $scope.loading = false;
        });
    }

    getData();

    const RhsaFilterListener = $scope.$on(Events.filters.rhsaSeverity,
        function (event, filter) {
            if (filter.length === 0) {
                return;
            }

            // rhsa severity filter can have multiple selected options
            // and it broadcasts a comma separated list of the options.
            const filters = filter.split(',')
                            .map(function (elem) { return elem.toUpperCase(); });

            $scope.rhsas = findAll(_allRhsas, function (rhsa) {
                return filters.indexOf(rhsa.severity.toUpperCase()) > -1;
            });
        });

    $scope.$on('$destroy', RhsaFilterListener);
}

componentsModule.controller('vulnerabilitiesPackageViewCtrl', 
  vulnerabilitiesPackageViewCtrl);