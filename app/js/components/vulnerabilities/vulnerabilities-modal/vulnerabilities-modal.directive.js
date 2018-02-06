'use strict';

var componentsModule = require('../../');

/**
 * @ngInject
 */
function vulnerabilitiesModalCtrl($scope,
                                  $location,
                                  Rule,
                                  System,
                                  SystemModalTabs) {

    $scope.getRuleHits = function (rhsa) {
        return rhsa.rule_hits === 1 ? '1 Hit' : `${rhsa.rule_hits} Hits`;
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

    function getData() {
        System.getVulnerabilities($scope.systemId)
            .then((system) => {
                console.log(system);
                $scope.system = system;
            });
    }

    $scope.$on('reload:data', getData);

    getData();
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
