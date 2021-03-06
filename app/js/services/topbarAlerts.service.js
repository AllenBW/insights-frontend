'use strict';

const servicesModule = require('./');
const sumBy = require('lodash/sumBy');
const remove = require('lodash/remove');

/**
 * @ngInject
 */
function TopbarAlertsService () {

    const service = {
        items: [],
        unackedCount: 0
    };

    function updateCounts () {
        service.unackedCount = sumBy(service.items, i => (i.acked) ? 0 : 1);
    }

    service.push = function (item) {
        service.items.push(item);
        updateCounts();
    };

    service.removeAll = function (type) {
        remove(service.items, {
            type: type
        });
        updateCounts();
    };

    return service;
}

servicesModule.service('TopbarAlertsService', TopbarAlertsService);
