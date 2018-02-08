'use strict';

var componentsModule = require('../../');
const find = require('lodash/find');
const remove = require('lodash/remove');

/**
 * @ngInject
 */
function vulnerabilitiesModalCtrl($scope,
                                  $location,
                                  $stateParams,
                                  Rule,
                                  System,
                                  SystemModalTabs) {

    $scope.getRuleHits = function (rhsa) {
        return rhsa.rule_hits === 1 ? '1 Hit' : `${rhsa.rule_hits} Hits`;
    };

    $scope.defaultExpanded = function (rhsa) {
        return (rhsa.id === $stateParams.rhsa_id ||
                find(rhsa.cves, {id: $stateParams.cve_id}));
    };

    $scope.goToRule = function () {
        const params = $location.search();
        params.selectedRule = $scope.selectedRule.rule_id;
        params.activeTab = SystemModalTabs.rules;
        params.selectedPackage = $scope.selectedRHSA.package.id;
        params.selectedRHSA = $scope.selectedRHSA.id;
        $location.search(params);
    };

    // function fetchRule (rule_id) {
    //     $scope.loadingRule = true;
    //     $scope.selectedRule = null;

    //     if (rule_id) {
    //         Rule.byId(rule_id, true).then((rule) => {
    //             $scope.selectedRule = rule.data;
    //             $scope.loadingRule = false;
    //         });
    //     }
    // }

    getData();
    function getData() {
        System.getVulnerabilities($scope.systemId)
            .then((system) => {
                if (system) {
                    system.rhsas = initRhsaOrder(system.rhsas);
                    $scope.system = system;
                }
            });
    }

    function initRhsaOrder(rhsas) {
        let first_rhsa;
        remove(rhsas, function (rhsa) {
            const bool = $scope.defaultExpanded(rhsa);

            if (bool) {
                first_rhsa = rhsa;
            }

            return bool;
        });

        if (first_rhsa) {
            rhsas.unshift(first_rhsa);
        }

        return rhsas;
    }

    $scope.$on('reload:data', getData);
}

function vulnerabilitiesModal() {
    return {
        templateUrl:
        'js/components/vulnerabilities/vulnerabilities-modal/vulnerabilities-modal.html',
        restrict: 'E',
        controller: vulnerabilitiesModalCtrl,
        replace: true,
        scope: {
            systemId: '<'
        }
    };
}

componentsModule.directive('vulnerabilitiesModal', vulnerabilitiesModal);
