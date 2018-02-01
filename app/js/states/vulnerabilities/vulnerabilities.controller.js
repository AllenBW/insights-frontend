/*global require*/
'use strict';

var statesModule = require('../');

/**
 * @ngInject
 *
 * Currently uses mock data
 */
function VulnerabilitiesCtrl($filter,
                             $location,
                             $scope,
                             InventoryService,
                             Utils,
                             Events,
                             Vulnerability,
                             SystemModalTabs,
                             VulnerabilitiesViews) {

    const DEFAULT_VIEW = VulnerabilitiesViews.package;
    let _allVulnerabilities;

    $scope.views = VulnerabilitiesViews;
    $scope.pager = new Utils.Pager();
    $scope.searchText = $location.search().searchText;
    $scope.vulnerabilities = [];
    $scope.selectedView = DEFAULT_VIEW;

    $scope.sorter = new Utils.Sorter({
        predicate: 'name',
        reverse: false},
        order);

    /*
     * Queries GET:/vulnerabilities and populates table data
     */
    function getData () {
        $scope.loading = true;
        let params = [];
        params.search_term = $scope.searchText;

        if ($scope.selectedView === $scope.views.package) {
            Vulnerability.getAll(params).then((vulnerabilities) => {
                $scope.allVulnerabilities = _allVulnerabilities = vulnerabilities;
                order();
                $scope.loading = false;
            });
        } else if ($scope.selectedView === $scope.views.rhsa) {
            Vulnerability.getAllRHSAs(params).then((vulnerabilities) => {
                $scope.allVulnerabilities = _allVulnerabilities = vulnerabilities;
                console.log(_allVulnerabilities);
                order();
                $scope.loading = false;
            });
        } else if ($scope.selectedView === $scope.views.cve) {
            Vulnerability.getCVEs(params).then((vulnerabilities) => {
                $scope.allVulnerabilities = _allVulnerabilities = vulnerabilities;
                order();
                $scope.loading = false;
            });
        }
    }

    function setVulnerabilities() {
        let page = $scope.pager.currentPage - 1;
        let pageSize = $scope.pager.perPage;
        let offset = page * pageSize;
        let arrayEnd = offset + pageSize < $scope.allVulnerabilities.total ?
                offset + pageSize : $scope.allVulnerabilities.total;
        $scope.vulnerabilities = $scope.allVulnerabilities.slice(offset, arrayEnd);
    }

    function reloadTable () {
        $scope.pager.currentPage = 1;
        setVulnerabilities();
    }

    function order () {
        $scope.allVulnerabilities = $filter('orderBy')(
            $scope.allVulnerabilities,
            [($scope.sorter.reverse ?
                '-' + $scope.sorter.predicate :
                $scope.sorter.predicate)]);

        reloadTable();
    }

    $scope.changeView = function (view) {
        if (view !== $scope.selectedView) {
            $scope.selectedView = view;
            getData();
        }
    };

    $scope.search = function (model) {
        if (!model || model === '') {
            $scope.allVulnerabilities = _allVulnerabilities;
        } else {
            $scope.allVulnerabilities = [];
            _allVulnerabilities.forEach((vulnerability) => {
                if (($scope.selectedView === $scope.views.package &&
                    vulnerability.name.indexOf(model) !== -1) ||
                    ($scope.selectedView === $scope.views.rhsa &&
                    vulnerability.id.indexOf(model) !== -1) ||
                    ($scope.selectedView === $scope.views.cve &&
                    vulnerability.id.indexOf(model) !== -1)) {
                    $scope.allVulnerabilities.push(vulnerability);
                }
            });
        }

        reloadTable();
    };

    $scope.searchRHSAs = function (model) {
        // TODO: rhsa search
        console.log(model);
    };

    $scope.searchCVEs = function (model) {
        //TODO: cve search
        console.log(model);
    };

    const reloadDataListener = $scope.$on('reload:data', getData);
    const filterResetListener = $scope.$on(Events.filters.reset, getData);
    $scope.$on('$destroy', function () {
        reloadDataListener();
        filterResetListener();
    });

    getData();
}

statesModule.controller('VulnerabilitiesCtrl', VulnerabilitiesCtrl);
