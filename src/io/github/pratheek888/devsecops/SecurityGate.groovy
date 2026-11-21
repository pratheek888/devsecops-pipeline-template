package io.github.pratheek888.devsecops

import com.cloudbees.groovy.cps.NonCPS
import groovy.json.JsonOutput
import groovy.json.JsonSlurper

/**
 * Policy engine for the security gate.
 *
 * Turns scanner reports (Trivy, Gitleaks, SonarQube quality gate) into normalised findings and
 * decides PASS / UNSTABLE / FAIL using a YAML policy with per-environment thresholds and
 * time-boxed exceptions.
 *
 * Everything is @NonCPS and works on plain maps and lists so results survive Jenkins
 * serialisation. The same class runs in Jenkins and in the CLI (GitHub Actions, local).
 */
class SecurityGate implements Serializable {

    static final List<String> SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']

    // ------------------------------------------------------------------ parsing

    /** Trivy JSON (fs, image, config): vulnerabilities, failed misconfigurations and secrets. */
    @NonCPS
    static List<Map> parseTrivy(String json, String source) {
        List<Map> out = []
        if (!json?.trim()) {
            return out
        }
        def report = new JsonSlurper().parseText(json)
        for (r in (report.Results ?: [])) {
            String target = r.Target as String
            for (v in (r.Vulnerabilities ?: [])) {
                out << [
                    source  : source,
                    type    : 'vulnerability',
                    id      : v.VulnerabilityID as String,
                    severity: normalise(v.Severity as String),
                    pkg     : v.PkgName as String,
                    version : v.InstalledVersion as String,
                    fixed   : (v.FixedVersion ?: null) as String,
                    title   : (v.Title ?: v.VulnerabilityID) as String,
                    location: target
                ]
            }
            for (m in (r.Misconfigurations ?: [])) {
                if ((m.Status ?: 'FAIL') != 'FAIL') {
                    continue
                }
                out << [
                    source  : source,
                    type    : 'misconfiguration',
                    id      : (m.AVDID ?: m.ID) as String,
                    severity: normalise(m.Severity as String),
                    pkg     : null,
                    fixed   : 'config',
                    title   : m.Title as String,
                    location: target
                ]
            }
            for (s in (r.Secrets ?: [])) {
                out << [
                    source  : source,
                    type    : 'secret',
                    id      : s.RuleID as String,
                    severity: 'SECRET',
                    pkg     : null,
                    fixed   : 'rotate',
                    title   : (s.Title ?: s.RuleID) as String,
                    location: "${target}:${s.StartLine ?: '?'}".toString()
                ]
            }
        }
        return out
    }

    /** Gitleaks JSON report (run with --redact, so no secret values are stored). */
    @NonCPS
    static List<Map> parseGitleaks(String json) {
        List<Map> out = []
        if (!json?.trim()) {
            return out
        }
        for (l in new JsonSlurper().parseText(json)) {
            String fingerprint = (l.Fingerprint ?: "${l.Commit}:${l.File}:${l.RuleID}:${l.StartLine}") as String
            out << [
                source  : 'gitleaks',
                type    : 'secret',
                id      : fingerprint,
                rule    : l.RuleID as String,
                severity: 'SECRET',
                pkg     : null,
                fixed   : 'rotate',
                title   : (l.Description ?: l.RuleID) as String,
                location: "${l.File}:${l.StartLine}".toString()
            ]
        }
        return out
    }

    // ------------------------------------------------------------------ policy

    /** Deep-merge `override` onto `base` (maps merge, everything else replaces). */
    @NonCPS
    static Map mergePolicy(Map base, Map override) {
        Map out = [:]
        out.putAll(base ?: [:])
        (override ?: [:]).each { k, v ->
            if (v instanceof Map && out[k] instanceof Map) {
                out[k] = mergePolicy(out[k] as Map, v as Map)
            } else if (k == 'exceptions' && v instanceof List && out[k] instanceof List) {
                out[k] = (out[k] as List) + (v as List)   // repo exceptions add to org-wide ones
            } else {
                out[k] = v
            }
        }
        return out
    }

    /** Effective rules for one environment: `defaults` overlaid with `environments.<env>`. */
    @NonCPS
    static Map effectiveRules(Map policy, String environment) {
        Map defaults = (policy?.defaults ?: [:]) as Map
        Map envRules = ((policy?.environments ?: [:]) as Map)[environment] as Map
        Map rules = mergePolicy(defaults, envRules ?: [:])
        Map vulns = (rules.vulnerabilities ?: [:]) as Map
        return [
            environment       : environment,
            failOn            : ((vulns.failOn ?: ['CRITICAL']) as List).collect { normalise(it as String) },
            warnOn            : ((vulns.warnOn ?: ['HIGH']) as List).collect { normalise(it as String) },
            ignoreUnfixed     : vulns.containsKey('ignoreUnfixed') ? vulns.ignoreUnfixed as boolean : true,
            maxSecrets        : (((rules.secrets ?: [:]) as Map).maxFindings ?: 0) as int,
            misconfigFailOn   : ((((rules.misconfigurations ?: [:]) as Map).failOn ?: ['CRITICAL']) as List)
                                    .collect { normalise(it as String) },
            requireQualityGate: ((rules.sast ?: [:]) as Map).containsKey('requireQualityGate') ?
                                    ((rules.sast as Map).requireQualityGate as boolean) : true
        ]
    }

    // ------------------------------------------------------------------ evaluation

    /**
     * @param policy      parsed policy YAML
     * @param environment dev / preprod / prod ...
     * @param findings    output of the parse* methods
     * @param sonarStatus SonarQube quality gate status (OK / ERROR / WARN) or null if SAST didn't run
     * @param today       ISO date (yyyy-MM-dd), used to expire exceptions
     */
    @NonCPS
    static Map evaluate(Map policy, String environment, List<Map> findings, String sonarStatus, String today) {
        Map rules = effectiveRules(policy, environment)
        List<Map> exceptions = ((policy?.exceptions ?: []) as List<Map>)
        exceptions = exceptions.collect { it + [expires: isoDate(it.expires)] }
        List<Map> active = exceptions.findAll { it.expires && (it.expires as String) >= today }
        List<Map> expired = exceptions.findAll { !it.expires || (it.expires as String) < today }

        List<Map> blocking = []
        List<Map> warnings = []
        List<Map> suppressed = []
        List<Map> ignored = []
        List<String> reasons = []

        for (Map f in findings) {
            Map exception = active.find { matches(it, f) }
            if (exception) {
                suppressed << (f + [suppressedBy: exception.reason, approvedBy: exception.approvedBy,
                                    expires: exception.expires])
                continue
            }
            switch (f.type) {
                case 'secret':
                    blocking << f   // counted against maxSecrets below
                    break
                case 'misconfiguration':
                    if (f.severity in rules.misconfigFailOn) {
                        blocking << f
                    } else if (f.severity in rules.warnOn) {
                        warnings << f
                    }
                    break
                default:
                    boolean unfixed = !f.fixed
                    if (unfixed && rules.ignoreUnfixed) {
                        ignored << f
                    } else if (f.severity in rules.failOn) {
                        blocking << f
                    } else if (f.severity in rules.warnOn) {
                        warnings << f
                    }
            }
        }

        // Secrets: allow up to maxSecrets (normally 0) before failing.
        List<Map> secrets = blocking.findAll { it.type == 'secret' }
        if (secrets.size() <= rules.maxSecrets) {
            blocking.removeAll(secrets)
            warnings.addAll(secrets)
        }

        if (secrets && secrets.size() > rules.maxSecrets) {
            reasons << "${secrets.size()} secret(s) detected (max ${rules.maxSecrets})".toString()
        }
        List<Map> blockingVulns = blocking.findAll { it.type == 'vulnerability' }
        if (blockingVulns) {
            reasons << "${blockingVulns.size()} fixable vulnerability(ies) at ${rules.failOn.join('/')}".toString()
        }
        List<Map> blockingMisconfig = blocking.findAll { it.type == 'misconfiguration' }
        if (blockingMisconfig) {
            reasons << "${blockingMisconfig.size()} misconfiguration(s) at ${rules.misconfigFailOn.join('/')}"
                .toString()
        }

        String decision = blocking ? 'FAIL' : (warnings ? 'UNSTABLE' : 'PASS')

        if (rules.requireQualityGate) {
            if (sonarStatus == 'ERROR') {
                decision = 'FAIL'
                reasons << 'SonarQube quality gate failed'
            } else if (sonarStatus == null) {
                reasons << 'SonarQube quality gate was not evaluated'
                if (decision == 'PASS') {
                    decision = 'UNSTABLE'
                }
            }
        }
        if (expired) {
            reasons << "${expired.size()} security exception(s) expired and no longer apply".toString()
        }
        if (!reasons && decision == 'UNSTABLE') {
            reasons << "${warnings.size()} finding(s) need attention (${rules.warnOn.join('/')})".toString()
        }

        return [
            decision         : decision,
            environment      : environment,
            reasons          : reasons,
            rules            : rules,
            counts           : counts(findings),
            blocking         : sortBySeverity(blocking),
            warnings         : sortBySeverity(warnings),
            suppressed       : suppressed,
            ignoredUnfixed   : ignored.size(),
            expiredExceptions: expired,
            sonarQualityGate : sonarStatus,
            evaluatedOn      : today
        ]
    }

    // ------------------------------------------------------------------ output

    @NonCPS
    static String markdown(Map result, int limit = 20) {
        StringBuilder sb = new StringBuilder()
        String icon = [PASS: '✅', UNSTABLE: '⚠️', FAIL: '❌'][result.decision]
        sb << "## ${icon} Security gate: ${result.decision} (${result.environment})\n\n"
        for (r in result.reasons) {
            sb << "- ${r}\n"
        }
        sb << '\n| Source | ' << SEVERITIES.join(' | ') << ' | SECRET |\n'
        sb << '|---' * (SEVERITIES.size() + 2) << '|\n'
        (result.counts as Map).each { src, c ->
            sb << "| ${src} | " << (SEVERITIES + ['SECRET']).collect { (c as Map)[it] ?: 0 }.join(' | ') << ' |\n'
        }
        section(sb, 'Blocking', result.blocking as List, limit)
        section(sb, 'Warnings', result.warnings as List, limit)
        if (result.suppressed) {
            sb << "\n### Suppressed by approved exceptions (${result.suppressed.size()})\n\n"
            for (s in result.suppressed) {
                sb << "- `${s.id}` ${s.pkg ?: ''}: ${s.suppressedBy} (approved by ${s.approvedBy}, " +
                      "expires ${s.expires})\n"
            }
        }
        if (result.expiredExceptions) {
            sb << '\n### Expired exceptions (now enforced)\n\n'
            for (e in result.expiredExceptions) {
                sb << "- `${e.id}` expired ${e.expires}\n"
            }
        }
        if (result.ignoredUnfixed) {
            sb << "\n_${result.ignoredUnfixed} vulnerability(ies) without an available fix were not counted._\n"
        }
        return sb.toString()
    }

    @NonCPS
    static String toJson(Map result) {
        return JsonOutput.prettyPrint(JsonOutput.toJson(result))
    }

    @NonCPS
    static String today() {
        return new Date().format('yyyy-MM-dd', TimeZone.getTimeZone('UTC'))
    }

    // ------------------------------------------------------------------ helpers

    @NonCPS
    private static void section(StringBuilder sb, String title, List<Map> items, int limit) {
        if (!items) {
            return
        }
        sb << "\n### ${title} (${items.size()})\n\n| Severity | ID | Package / target | Fix | Title |\n|---|---|---|---|---|\n"
        for (f in items.take(limit)) {
            String where = f.pkg ? "${f.pkg} ${f.version ?: ''}".trim() : f.location
            sb << "| ${f.severity} | `${f.id}` | ${where} | ${f.fixed ?: '-'} | ${(f.title ?: '').take(80)} |\n"
        }
        if (items.size() > limit) {
            sb << "\n…and ${items.size() - limit} more (see reports/security-gate.json)\n"
        }
    }

    /** YAML turns 2026-12-31 into a Date; keep everything as yyyy-MM-dd strings. */
    @NonCPS
    static String isoDate(Object value) {
        if (value == null) {
            return null
        }
        if (value instanceof Date) {
            return (value as Date).format('yyyy-MM-dd', TimeZone.getTimeZone('UTC'))
        }
        return value.toString().take(10)
    }

    @NonCPS
    private static boolean matches(Map exception, Map finding) {
        if (exception.id != finding.id) {
            return false
        }
        if (exception['package'] && exception['package'] != finding.pkg) {
            return false
        }
        return !exception.source || exception.source == finding.source
    }

    @NonCPS
    private static Map counts(List<Map> findings) {
        Map out = [:]
        for (f in findings) {
            Map c = (out[f.source] ?: [:]) as Map
            c[f.severity] = ((c[f.severity] ?: 0) as int) + 1
            out[f.source] = c
        }
        return out
    }

    @NonCPS
    private static List<Map> sortBySeverity(List<Map> findings) {
        List<String> order = ['SECRET'] + SEVERITIES
        return findings.sort(false) { a, b -> order.indexOf(a.severity) <=> order.indexOf(b.severity) ?: a.id <=> b.id }
    }

    @NonCPS
    private static String normalise(String severity) {
        String s = (severity ?: 'UNKNOWN').toUpperCase()
        return s in SEVERITIES ? s : 'UNKNOWN'
    }
}
