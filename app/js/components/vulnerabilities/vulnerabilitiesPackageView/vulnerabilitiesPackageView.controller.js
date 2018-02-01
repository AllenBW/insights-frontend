'use strict';

const componentsModule = require('../../');
const findAll = require('lodash/filter');

/**
 * @ngInject
 */
function vulnerabilitiesPackageViewCtrl($scope,
                                  $stateParams,
                                  $location,
                                  SystemModalTabs,
                                  Vulnerability,
                                  Rule,
                                  Events) {

    const package_id = $stateParams.package_id;
    let _allRhsas;

    $scope.loading = false;
    $scope.showCVEs = false;

    // TODO server side search
    $scope.search = function (model) {
        $scope.rhsas = findAll(_allRhsas, function (rhsa) {
            return rhsa.id.toUpperCase().indexOf(model.toUpperCase()) > -1;
        });
    };

    function initPageHeader() {
        $scope.pageHeaderSubtitle = [`Release Date: ${$scope.package.release_date}`,
                           `Version: ${$scope.package.version}`,
                           `RHSA Count: ${$scope.package.rhsa_count}`,
                           `CVE Count: ${$scope.package.cve_count}`];
    }

    function getData() {
        $scope.loading = true;
        Vulnerability.getPackage(package_id).then((pkg) => {
            $scope.package = pkg;
            $scope.rhsas = _allRhsas = pkg.rhsas;
            initPageHeader();
            $scope.loading = false;
        });
    }

    getData();

    function round (x, to) {
        return Math.ceil(x / to) * to;
    }

    $scope.indexMe = function (index) {
        var windowWidth = document.documentElement.clientWidth;
        var windowSm    = 768;
        var windowMd    = 992;

        if (windowWidth < windowSm) {
            $scope.cveOrder = index;
        } else if (windowWidth >= windowSm && windowWidth < windowMd) {
            $scope.cveOrder = round(index, 2);
        } else if (windowWidth >= windowMd) {
            $scope.cveOrder = round(index, 4);
        }
    };

    $scope.toggleShowCVEs = function (rhsa) {
        if ($scope.selectedRHSA === rhsa || !rhsa) {
            delete $scope.selectedRHSA;
        } else {
            $scope.selectedRHSA = rhsa;
            $scope.selectCVE(rhsa.cves[0]);
        }
    };

    $scope.isSelected = function (rhsa) {
        if (rhsa && $scope.selectedRHSA) {
            return rhsa.id === $scope.selectedRHSA.id;
        }

        return false;
    };

    $scope.getRuleHits = function (rhsa) {
        return rhsa.rule_hits === 1 ? '1 Hit' : `${rhsa.rule_hits} Hits`;
    };

    $scope.selectCVE = function (cve) {
        if ($scope.selectedCVE !== cve) {
            $scope.selectedCVE = cve;
            fetchRule($scope.selectedCVE.insights_rule);
        }
    };

    $scope.goToRule = function () {
        const params = $location.search();
        params.selectedRule = $scope.selectedRule.rule_id;
        params.activeTab = SystemModalTabs.rules;
        params.selectedPackage = $scope.selectedRHSA.package.id;
        params.selectedRHSA = $scope.selectedRHSA.id;
        $location.search(params);
    };

    function fetchRule (rule_id) {
        $scope.loadingRule = true;
        $scope.selectedRule = null;

        if (rule_id) {
            Rule.byId(rule_id, true).then((rule) => {
                $scope.selectedRule = rule.data;
                $scope.loadingRule = false;
            });
        }
    }

    const RhsaFilterListener = $scope.$on(Events.filters.rhsaSeverity,
        function (event, filter) {
            if (filter.length === 0) {
                $scope.rhsas = _allRhsas;
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
