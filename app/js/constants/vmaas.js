'use strict';
var constantsModule = require('./');

const SYSTEMS = {
    'kinlaw-rhel-vm': {
        system_id: 'f7473238-1953-415f-8de6-a8da92975a64',
        system_type_id: 105,
        toString: 'kinlaw-rhel-vm',
        account_number: '540155',
        report_count: 2,
        last_check_in: '2018-01-17T13:16:31.000Z'
    },
    'kinlaw-rhel-vm4': {
        system_id: '66a6d090-e1dc-4036-b29f-c0b8cfde433d',
        system_type_id: 105,
        toString: 'kinlaw-rhel-vm4',
        account_number: '540155',
        report_count: 6,
        last_check_in: '2018-01-17T13:16:31.000Z'
    }
};

const CVES = {
    'CVE-2017-6462': {
        id: 'CVE-2017-6462',
        impact: 'low',
        public_date: '2017-03-21',
        iava: '2017-A-0084',
        cwe: 'CWE-20',
        systems_affected: 2,
        package_count: 1,
        score: 6.4,
        description: 'A vulnerability was found in NTP, in the parsing of ' +
             'packets from the /dev/datum device. A malicious device could send ' +
             'crafted messages, causing ntpd to crash. Find out more about ' +
             'CVE-2017-6462 from the MITRE CVE dictionary dictionary and NIST NVD.',
        systems: [SYSTEMS['kinlaw-rhel-vm'], SYSTEMS['kinlaw-rhel-vm4']],
        link: 'https://access.redhat.com/security/cve/cve-2017-6462'
    },
    'CVE-2017-6463': {
        id: 'CVE-2017-6463',
        impact: 'moderate',
        public_date: '2017-03-21',
        iava: '2017-A-0084',
        cwe: 'CWE-20',
        systems_affected: 2,
        package_count: 1,
        score: 6.5,
        description: 'A vulnerability was discovered in the NTP server\'s ' +
             'parsing of configuration directives. A remote, authenticated ' +
             'attacker could cause ntpd to crash by sending a crafted message.' +
             'Find out more about CVE-2017-6463 from the MITRE CVE dictionary' +
             ' and NIST NVD.',
        systems: [SYSTEMS['kinlaw-rhel-vm'], SYSTEMS['kinlaw-rhel-vm4']],
        link: 'https://access.redhat.com/security/cve/CVE-2017-6463'
    },
    'CVE-2017-5754': {
        id: 'CVE-2017-5754',
        impact: 'important',
        public_date: '2018-01-03',
        iava: null,
        cew: null,
        systems_affected: 2,
        package_count: 1,
        score: 5.5,
        description: `
            An industry-wide issue was found in the way many modern microprocessor designs
            have implemented speculative execution of instructions (a commonly used
            performance optimization). There are three primary variants of the issue which
            differ in the way the speculative execution can be exploited. Variant
            CVE-2017-5754 relies on the fact that, on impacted microprocessors, during
            speculative execution of instruction permission faults, exception generation
            triggered by a faulting access is suppressed until the retirement of the whole
            instruction block. In a combination with the fact that memory accesses may
            populate the cache even when the block is being dropped and never
            committed (executed), an unprivileged local attacker could use this flaw
            to read privileged (kernel space) memory by conducting targeted cache
            side-channel attacks.

            Note: CVE-2017-5754 affects Intel x86-64 microprocessors.
            AMD x86-64 microprocessors are not affected by this issue.`,
        systems: [SYSTEMS['kinlaw-rhel-vm'], SYSTEMS['kinlaw-rhel-vm4']],
        link: 'https://access.redhat.com/security/cve/CVE-2017-5754',
        insights_rule: 'CVE_2017_5754_kernel|KERNEL_CVE_2017_5754_INTEL'
    },
    'CVE-2017-1000251': {
        id: 'CVE-2017-1000251',
        impact: 'important',
        public_date: '2017-09-12',
        iava: null,
        cwe: 'CWE-121',
        systems_affected: 2,
        package_count: 1,
        score: 6.8,
        description: `
        A stack buffer overflow flaw was found in the way the Bluetooth subsystem
        of the Linux kernel processed pending L2CAP configuration responses from
        a client. On systems with the stack protection feature enabled in the kernel
        (CONFIG_CC_STACKPROTECTOR=y, which is enabled on all architectures other than
        s390x and ppc64[le]), an unauthenticated attacker able to initiate a
        connection to a system via Bluetooth could use this flaw to crash the system.
        Due to the nature of the stack protection feature, code execution cannot be
        fully ruled out, although we believe it is unlikely. On systems without the
        stack protection feature (ppc64[le]; the Bluetooth modules are not built
        on s390x), an unauthenticated attacker able to initiate a connection to a
        system via Bluetooth could use this flaw to remotely execute arbitrary code
        on the system with ring 0 (kernel) privileges.`,
        systems: [SYSTEMS['kinlaw-rhel-vm'], SYSTEMS['kinlaw-rhel-vm4']],
        link: 'https://access.redhat.com/security/cve/CVE-2017-1000251',
        insights_rule: 'CVE_2017_1000251_kernel_blueborne|' +
                       'KERNEL_CVE_2017_1000251_POSSIBLE_DOS'
    },
    'CVE-2017-1000364': {
        id: 'CVE-2017-1000364',
        impact: 'important',
        public_date: '2017-06-19',
        iava: null,
        cwe: null,
        systems_affected: 2,
        package_count: 1,
        score: 6.2,
        description: `
        A flaw was found in the way memory was being allocated on the stack for
        user space binaries. If heap (or different memory region) and stack memory
        regions were adjacent to each other, an attacker could use this flaw to jump
        over the stack guard gap, cause controlled memory corruption on process stack
        or the adjacent memory region, and thus increase their privileges on the
        system. This is a kernel-side mitigation which increases the stack guard gap
        size from one page to 1 MiB to make successful exploitation of this issue
        more difficult.`,
        systems: [SYSTEMS['kinlaw-rhel-vm'], SYSTEMS['kinlaw-rhel-vm4']],
        link: 'https://access.redhat.com/security/cve/CVE-2017-1000364',
        insights_rule: 'CVE_2017_1000366_glibc|' +
                       'CVE_2017_1000364_KERNEL_CVE_2017_1000366_GLIBC_EXPLOITABLE'
    },
    'CVE-2017-7184': {
        id: 'CVE-2017-7184',
        impact: 'important',
        public_date: '2017-03-29',
        iava: null,
        cwe: 'CWE-122',
        systems_affected: 2,
        package_count: 1,
        score: 7.8,
        description: `
        Out-of-bounds kernel heap access vulnerability was found in xfrm,
        kernel's IP framework for transforming packets. An error dealing with
        netlink messages from an unprivileged user leads to arbitrary read/write
        and privilege escalation.`,
        systems: [SYSTEMS['kinlaw-rhel-vm'], SYSTEMS['kinlaw-rhel-vm4']],
        link: 'https://access.redhat.com/security/cve/CVE-2017-7184',
        insights_rule: 'CVE_2017_7184_kernel|KERNEL_CVE_2017_7184_EXPLOITABLE_2'
    }
};

const RHSAS = {
    'RHSA-2017:3071': {
        id: 'RHSA-2017:3071',
        type: 'Security Advisory',
        synopsis: 'ntp security update',
        severity: 'moderate',
        systems_affected: 2,
        issued: '2017-10-26',
        updated: '2017-10-26',
        package_count: 1,
        cve_count: 2,
        summary: 'An update for ntp is now available for Red Hat Enterprise Linux ' +
                 '6. Red Hat Product Security has rated this update as having ' +
                 'a security impact of Moderate. A Common Vulnerability Scoring ' +
                 'System (CVSS) base score, which gives a detailed severity ' +
                 'rating, is available for each vulnerability from the CVE ' +
                 'link(s) in the References section.',
        description: 'An update for ntp is now available for Red Hat Enterprise ' +
                 'Linux 6. Red Hat Product Security has rated this update as ' +
                 'Scoring having a security impact of Moderate. A Common ' +
                 'Vulnerability System (CVSS) base score, which gives a detailed ' +
                 'severity rating, is available for each vulnerability from the ' +
                 'CVE link(s) in the References section.',
        solution: `
            For details on how to apply this update, which includes the changes
            described in this advisory, refer to:

            https://access.redhat.com/articles/11258

            After installing this update, the ntpd daemon will restart automatically.
        `,
        cves: [CVES['CVE-2017-6462'], CVES['CVE-2017-6463']],
        systems: [SYSTEMS['kinlaw-rhel-vm'], SYSTEMS['kinlaw-rhel-vm4']],
        affected_products: ['Red Hat Enterprise Linux Server 6 x86_64',
                    'Red Hat Enterprise Linux Server 6 i386',
                    'Red Hat Enterprise Linux Workstation 6 x86_64',
                    'Red Hat Enterprise Linux Workstation 6 i386',
                    'Red Hat Enterprise Linux Desktop 6 x86_64',
                    'Red Hat Enterprise Linux Desktop 6 i386',
                    'Red Hat Enterprise Linux for IBM z Systems 6 s390x',
                    'Red Hat Enterprise Linux for Power, big endian 6 ppc64',
                    'Red Hat Enterprise Linux for Scientific Computing 6 x86_64'],
        rule_hits: 0
    },
    'RHSA-2018:0007': {
        id: 'RHSA-2018:0007',
        type: 'Security Advisory',
        synopsis: 'kernel security update',
        severity: 'important',
        systems_affected: 2,
        issued: '2018-01-03',
        updated: '2018-01-03',
        package_count: 1,
        cve_count: 1,
        summary:'An update for kernel is now available for Red Hat Enterprise Linux 7.',
        description: `
            An industry-wide issue was found in the way many modern microprocessor designs
            have implemented speculative execution of instructions (a commonly used
            performance optimization). There are three primary variants of the issue which
            differ in the way the speculative execution can be exploited.`,
        solution: `
            For details on how to apply this update, which includes the changes
            described in this advisory, refer to:

            https://access.redhat.com/articles/11258

            The system must be rebooted for this update to take effect.
        `,
        cves: [CVES['CVE-2017-5754']],
        systems: [SYSTEMS['kinlaw-rhel-vm'], SYSTEMS['kinlaw-rhel-vm4']],
        affected_products: ['Red Hat Enterprise Linux Server 7 x86_64',
                    'Red Hat Enterprise Linux Server - AUS 7.4 x86_64',
                    'Red Hat Enterprise Linux Workstation 7 x86_64',
                    'Red Hat Enterprise Linux Desktop 7 x86_64',
                    'Red Hat Enterprise Linux for IBM z Systems 7 s390x',
                    'Red Hat Enterprise Linux for Power, big endian 7 ppc64'],
        rule_hits: 1
    },
    'RHSA-2017:2679': {
        id:'RHSA-2017:2679',
        type: 'Security Advisory',
        synopsis: 'kernel security update',
        severity: 'important',
        systems_affected: 2,
        issued: '2017-09-12',
        updated: '2017-09-12',
        package_count: 1,
        cve_count: 1,
        summary: 'An update for kernel is now available for Red Hat Enterprise Linux 7.',
        description:`
            A stack buffer overflow flaw was found in the way the Bluetooth subsystem of
            the Linux kernel processed pending L2CAP configuration responses from
            a client.`,
        solution: `
            For details on how to apply this update, which includes the changes
            described in this advisory, refer to:

            https://access.redhat.com/articles/11258

            The system must be rebooted for this update to take effect.`,
        cves: [CVES['CVE-2017-1000251']],
        systems: [SYSTEMS['kinlaw-rhel-vm'], SYSTEMS['kinlaw-rhel-vm4']],
        affected_products: ['Red Hat Enterprise Linux Server 7 x86_64',
                    'Red Hat Enterprise Linux Server - AUS 7.4 x86_64',
                    'Red Hat Enterprise Linux Workstation 7 x86_64',
                    'Red Hat Enterprise Linux Desktop 7 x86_64'],
        rule_hits: 1
    },
    'RHSA-2017:1484': {
        id:'RHSA-2017:1484',
        type: 'Security Advisory',
        synopsis: 'kernel security update',
        severity: 'important',
        systems_affected: 2,
        issued: '2017-06-19',
        updated: '2017-06-19',
        package_count: 1,
        cve_count: 1,
        summary: 'An update for kernel is now available for Red Hat Enterprise Linux 7.',
        description:`
        A flaw was found in the way memory was being allocated on the stack for
        user space binaries. If heap (or different memory region) and stack memory regions
        were adjacent to each other, an attacker could use this flaw to jump over the
        stack guard gap, cause controlled memory corruption on process stack or
        the adjacent memory region, and thus increase their privileges on the system.
        This is a kernel-side mitigation which increases the stack guard gap size
        from one page to 1 MiB to make successful exploitation of this issue
        more difficult.`,
        solution: `
            For details on how to apply this update, which includes the changes
            described in this advisory, refer to:

            https://access.redhat.com/articles/11258

            The system must be rebooted for this update to take effect.
        `,
        cves: [CVES['CVE-2017-1000364']],
        systems: [SYSTEMS['kinlaw-rhel-vm'], SYSTEMS['kinlaw-rhel-vm4']],
        affected_products: ['Red Hat Enterprise Linux Server 7 x86_64',
                    'Red Hat Enterprise Linux Workstation 7 x86_64',
                    'Red Hat Enterprise Linux Desktop 7 x86_64',
                    'Red Hat Enterprise Linux for IBM z Systems 7 s390x',
                    'Red Hat Enterprise Linux Server - AUS 7.4 x86_64'],
        rule_hits: 1
    },
    'RHSA-2017:2930': {
        id:'RHSA-2017:2930',
        type: 'Security Advisory',
        synopsis: 'kernel security update',
        severity: 'important',
        systems_affected: 2,
        issued: '2017-10-19',
        updated: '2017-10-19',
        package_count: 1,
        cve_count: 1,
        summary: 'An update for kernel is now available for Red Hat Enterprise Linux 7.',
        description:`
        Security Fix(es):
        Out-of-bounds kernel heap access vulnerability was found in xfrm, kernel's IP
        framework for transforming packets.
        A race condition issue leading to a use-after-free flaw was found in the way
        the raw packet sockets are implemented in the Linux kernel networking subsystem
        handling synchronization. A local user able to open a raw packet socket
        (requires the CAP_NET_RAW capability) could use this flaw to elevate their
        privileges on the system.

        An exploitable memory corruption flaw was found in the Linux kernel.
        The append path can be erroneously switched from UFO to non-UFO in
        ip_ufo_append_data() when building an UFO packet with MSG_MORE option.
        If unprivileged user namespaces are available, this flaw can be exploited
        to gain root privileges.

        A flaw was found in the Linux networking subsystem where a local attacker with
        CAP_NET_ADMIN capabilities could cause an out-of-bounds memory access by
        creating a smaller-than-expected ICMP header and sending to its destination
        via sendto().

        Kernel memory corruption due to a buffer overflow was found in
        brcmf_cfg80211_mgmt_tx() function in Linux kernels from v3.9-rc1 to v4.13-rc1.
        The vulnerability can be triggered by sending a crafted NL80211_CMD_FRAME packet
        via netlink. This flaw is unlikely to be triggered remotely as certain userspace
        code is needed for this. An unprivileged local user could use this flaw to
        induce kernel memory corruption on the system, leading to a crash. Due to the
        nature of the flaw, privilege escalation cannot be fully ruled out, although
        it is unlikely.

        An integer overflow vulnerability in ip6_find_1stfragopt() function was found.
        A local attacker that has privileges (of CAP_NET_RAW) to open raw socket can
        cause an infinite loop inside the ip6_find_1stfragopt() function.

        A kernel data leak due to an out-of-bound read was found in the Linux kernel in
        inet_diag_msg_sctp{,l}addr_fill() and sctp_get_sctp_info() functions
        present since version 4.7-rc1 through version 4.13. A data leak happens when
        these functions fill in sockaddr data structures used to export
        socket's diagnostic information. As a result, up to 100 bytes of the slab
        data could be leaked to a userspace.

        The mq_notify function in the Linux kernel through 4.11.9 does not set the sock
        pointer to NULL upon entry into the retry logic. During a user-space close of a
        Netlink socket, it allows attackers to possibly cause a situation where a value
        may be used after being freed (use-after-free) which may lead to memory
        corruption or other unspecified other impact.

        A divide-by-zero vulnerability was found in the __tcp_select_window function in
        the Linux kernel. This can result in a kernel panic causing a local denial
        of service.`,
        solution: `
            For details on how to apply this update, which includes the changes
            described in this advisory, refer to:

            https://access.redhat.com/articles/11258

            The system must be rebooted for this update to take effect.
        `,
        cves: [CVES['CVE-2017-7184']],
        systems: [SYSTEMS['kinlaw-rhel-vm'], SYSTEMS['kinlaw-rhel-vm4']],
        affected_products: ['Red Hat Enterprise Linux Server 7 x86_64',
                    'Red Hat Enterprise Linux Server - AUS 7.4 x86_64',
                    'Red Hat Enterprise Linux Workstation 7 x86_64',
                    'Red Hat Enterprise Linux Desktop 7 x86_64',
                    'Red Hat Enterprise Linux for IBM z Systems 7 s390x'],
        rule_hits: 1
    }
};

const PACKAGES_NO_CVES = [{
    id: 'ntp',
    release_date: '2017-01-01',
    critical_count: 0,
    important_count: 0,
    moderate_count: 1,
    low_count: 0,
    rhsa_count: 1,
    cve_count: RHSAS['RHSA-2017:3071'].cves.length,
    systems_affected: 2,
    version: '4.0',
    description: `
        The Network Time Protocol (NTP) is used to synchronize a computer's
        time with another reference time source. This package includes ntpd
        (a daemon which continuously adjusts system time) and utilities used
        to query and configure the ntpd daemon.

        Perl scripts ntp-wait and ntptrace are in the ntp-perl package,
        ntpdate is in the ntpdate package and sntp is in the sntp package.
        The documentation is in the ntp-doc package.`,
    systems: [SYSTEMS['kinlaw-rhel-vm'], SYSTEMS['kinlaw-rhel-vm4']],
    rhsas: [RHSAS['RHSA-2017:3071']]
}, {
    id: 'kernel',
    release_date: '2014-06-10',
    systems_affected: 2,
    critical_count: 0,
    important_count: 4,
    moderate_count: 0,
    low_count: 0,
    rhsa_count: 4,
    cve_count: RHSAS['RHSA-2017:2930'].cves.length +
                RHSAS['RHSA-2017:1484'].cves.length +
                RHSAS['RHSA-2017:2679'].cves.length +
                RHSAS['RHSA-2018:0007'].cves.length,
    version: '3.10.0-693',
    description: `
        The kernel meta package.`,
    systems: [SYSTEMS['kinlaw-rhel-vm'], SYSTEMS['kinlaw-rhel-vm4']],
    rhsas: [RHSAS['RHSA-2017:2930'], RHSAS['RHSA-2017:1484'],
            RHSAS['RHSA-2017:2679'], RHSAS['RHSA-2018:0007']]
}];

constantsModule.constant('VMAAS_PACKAGES_NOCVE', PACKAGES_NO_CVES);

/**
 * app/js/api/vulnerability.js:getCVE
 *
 *     data_needed = {
 *         id: String/Number,
 *         systems_affected: Number,
 *         package_count: Number,
 *         public_date: Date,
 *         impact: String,
 *         systems: Array[Object],
 *         packages: Array[Object],
 *         description: String,
 *         link: String
 *     }
 */
constantsModule.constant('VMAAS_GET_CVE', (function () {
    const obj = {};
    Object.keys(CVES).forEach(function (key) {
        const cve = CVES[key];
        const packages = key === 'CVE-2017-6462' ||
                         key === 'CVE-2017-6463' ?
                         [PACKAGES_NO_CVES[0]] :
                         [PACKAGES_NO_CVES[1]];
        obj[key] = {};
        obj[key].id = cve.id;
        obj[key].systems_affected = cve.systems_affected;
        obj[key].systems = cve.systems;
        obj[key].package_count = cve.package_count;
        obj[key].public_date = cve.public_date;
        obj[key].packages = packages;
        obj[key].impact = cve.impact;
        obj[key].description = cve.description;
        obj[key].link = cve.link;
    });

    return obj;
})());

/**
 * app/js/api/vulnerability.js:getCVEs
 *
 *     data_needed = {
 *         id: String/Number,
 *         systems_affected: Number,
 *         package_count: Number,
 *         public_date: Date
 *     }
 */
constantsModule.constant('VMAAS_GET_ALL_CVES', (function () {
    const array = [];
    Object.keys(CVES).forEach(function (key) {
        const cve = CVES[key];
        array.push({
            id: cve.id,
            systems_affected: cve.systems_affected,
            package_count: cve.package_count,
            public_date: cve.public_date
        });
    });

    return array;
})());

/**
 * app/js/api/vulnerability.js:getPackages
 *
 *     data_needed = {
 *         name: String,
 *         systems_affected: Number,
 *         cve_count: Number,
 *         rhsa_count: Number,
 *         release_date: Date
 *     }
 */
constantsModule.constant('VMAAS_GET_ALL_PACKAGES', (function () {
    const array = [];
    PACKAGES_NO_CVES.forEach(function (obj) {
        array.push({
            id: obj.id,
            systems_affected: obj.systems_affected,
            rhsa_count: obj.rhsa_count,
            cve_count: obj.cve_count,
            release_date: obj.release_date
        });
    });

    return array;
})());

/**
 * app/js/api/vulnerability.js:getRHSA
 *
 *     data_needed = {
 *         id: String,
 *         severity: String,
 *         systems: Array[Object],
 *         packages: Array[Object],
 *         affected_products: Array[String],
 *         solution: String,
 *         topic: String,
 *         type: String,
 *         description: String,
 *         cve_count: Number,
 *         issued: Date,
 *         link: String
 *     }
 */
constantsModule.constant('VMAAS_GET_RHSA', (function () {
    const obj = {};
    Object.keys(RHSAS).forEach(function (key) {
        const rhsa = RHSAS[key];
        obj[key] = {};

        if (key === 'RHSA-2017:3071') {
            obj[key].packages = [PACKAGES_NO_CVES[0]];
        } else {
            obj[key].packages = [PACKAGES_NO_CVES[1]];
        }

        obj[key].id = rhsa.id;
        obj[key].severity = rhsa.severity;
        obj[key].systems = rhsa.systems;
        obj[key].systems_affected = rhsa.systems_affected;
        obj[key].description = rhsa.description;
        obj[key].affected_products = rhsa.affected_products;
        obj[key].solution = rhsa.solution;
        obj[key].type = rhsa.type;
        obj[key].cve_count = rhsa.cve_count;
        obj[key].issued = rhsa.issued;
        obj[key].topic = rhsa.summary;
        obj[key].link = `https://access.redhat.com/errata/${rhsa.id}`;
    });

    return obj;
})());

/**
 * app/js/api/vulnerability.js:getRHSAs
 *
 *     data_needed = {
 *         id: String,
 *         severity: String,
 *         systems_affected: Number,
 *         package_count: Number,
 *         cve_count: Number,
 *         issued: Date,
 *         updated_date: Date
 *     }
 */
constantsModule.constant('VMAAS_GET_ALL_RHSAS', (function () {
    const array = [];
    Object.keys(RHSAS).forEach(function (key) {
        const rhsa = RHSAS[key];
        array.push({
            id: rhsa.id,
            severity: rhsa.severity,
            systems_affected: rhsa.systems_affected,
            package_count: rhsa.package_count,
            cve_count: rhsa.cve_count,
            issued: rhsa.issued,
            updated: rhsa.updated
        });
    });

    return array;
})());

/**
 * app/js/api/system.js:getVulnerabilities
 */
constantsModule.constant('VMAAS_GET_SYSTEM', (function () {
    const obj = {};
    Object.keys(SYSTEMS).forEach(function (key) {
        const sys = SYSTEMS[key];

        if (key === 'kinlaw-rhel-vm') {
            PACKAGES_NO_CVES[0].latest_version = '4.0';
            PACKAGES_NO_CVES[0].system_version = '3.0';
            PACKAGES_NO_CVES[0].fixed_version = '3.0';
            PACKAGES_NO_CVES[1].latest_version = '3.10.0-693';
            PACKAGES_NO_CVES[1].system_version = '3.10.0-693';
            PACKAGES_NO_CVES[1].fixed_version = '3.10.0-693';
        }

        if (key === 'kinlaw-rhel-vm4') {
            PACKAGES_NO_CVES[0].latest_version = '4.0';
            PACKAGES_NO_CVES[0].system_version = '4.0';
            PACKAGES_NO_CVES[0].fixed_version = '3.0';
            PACKAGES_NO_CVES[1].latest_version = '3.10.0-693';
            PACKAGES_NO_CVES[1].system_version = '3.10.0-693';
            PACKAGES_NO_CVES[1].fixed_version = '3.10.0-693';
        }

        Object.keys(RHSAS).forEach(function (k) {
            const rhsa = RHSAS[k];

            if (k === 'RHSA-2017:3071') {
                rhsa.packages = [PACKAGES_NO_CVES[0]];
            } else {
                rhsa.packages = [PACKAGES_NO_CVES[1]];
            }
        });

        obj[key] = {};
        obj[key].system_id = sys.system_id;
        obj[key].system_type = sys.system_type;
        obj[key].toString = sys.toString;
        obj[key].account_number = sys.account_number;
        obj[key].report_count = sys.report_count;
        obj[key].last_check_in = sys.last_check_in;
        obj[key].rhsas = [RHSAS['RHSA-2017:2930'],
                          RHSAS['RHSA-2017:3071'],
                          RHSAS['RHSA-2017:1484'],
                          RHSAS['RHSA-2017:2679'],
                          RHSAS['RHSA-2018:0007']];
    });

    return obj;
})());

constantsModule.constant('VMAAS_SYSTEMS', [{
    system_id: 'f7473238-1953-415f-8de6-a8da92975a64',
    system_type_id: 105,
    toString: 'kinlaw-rhel-vm',
    account_number: '540155',
    report_count: 2,
    last_check_in: '2018-01-17T13:16:31.000Z',
    packages: PACKAGES_NO_CVES,
    rhsas: [RHSAS['RHSA-2017:2930'], RHSAS['RHSA-2017:3071'],
            RHSAS['RHSA-2017:1484'], RHSAS['RHSA-2017:2679'],
            RHSAS['RHSA-2018:0007']]
}, {
    system_id: '66a6d090-e1dc-4036-b29f-c0b8cfde433d',
    system_type_id: 105,
    toString: 'kinlaw-rhel-vm4',
    account_number: '540155',
    report_count: 6,
    last_check_in: '2018-01-17T13:16:31.000Z',
    packages: PACKAGES_NO_CVES,
    rhsas: [RHSAS['RHSA-2017:2930'], RHSAS['RHSA-2017:3071'],
            RHSAS['RHSA-2017:1484'], RHSAS['RHSA-2017:2679'],
            RHSAS['RHSA-2018:0007']]
}]);
