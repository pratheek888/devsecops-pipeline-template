package io.github.pratheek888.devsecops

import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.yaml.snakeyaml.LoaderOptions
import org.yaml.snakeyaml.Yaml
import org.yaml.snakeyaml.constructor.SafeConstructor

import static org.junit.jupiter.api.Assertions.assertEquals
import static org.junit.jupiter.api.Assertions.assertTrue
import static org.junit.jupiter.api.Assertions.assertFalse

class SecurityGateTest {

    static final String TODAY = '2026-11-22'
    Map policy
    List<Map> image
    List<Map> fs
    List<Map> secrets

    static String fixture(String name) {
        return SecurityGateTest.getResourceAsStream("/reports/${name}").getText('UTF-8')
    }

    static Map loadYaml(String text) {
        return new Yaml(new SafeConstructor(new LoaderOptions())).load(text) as Map
    }

    @BeforeEach
    void setUp() {
        policy = loadYaml(SecurityGateTest.getResourceAsStream(
            '/io/github/pratheek888/devsecops/default-policy.yaml').getText('UTF-8'))
        image = SecurityGate.parseTrivy(fixture('trivy-image.json'), 'image')
        fs = SecurityGate.parseTrivy(fixture('trivy-fs.json'), 'dependencies')
        secrets = SecurityGate.parseGitleaks(fixture('gitleaks.json'))
    }

    @Test
    void parsesVulnerabilitiesMisconfigsAndSecrets() {
        assertEquals(5, image.size())
        assertEquals(['CRITICAL', 'HIGH', 'CRITICAL', 'MEDIUM', 'HIGH'], image*.severity)
        assertEquals(2, fs.size(), 'PASSed misconfig checks are not findings')
        assertEquals(['AVD-DS-0002', 'AVD-DS-0026'], fs*.id)
        assertEquals('secret', secrets[0].type)
        assertEquals('src/main/resources/application.properties:12', secrets[0].location)
        assertTrue(SecurityGate.parseTrivy('', 'x').isEmpty())
    }

    @Test
    void fixableCriticalFailsInDev() {
        Map r = SecurityGate.evaluate(policy, 'dev', image, 'OK', TODAY)
        assertEquals('FAIL', r.decision)
        assertEquals(['CVE-2026-0001'], r.blocking*.id)
        assertEquals(['CVE-2026-0002', 'CVE-2026-0005'], r.warnings*.id.sort())
        assertEquals(1, r.ignoredUnfixed, 'unfixed glibc CVE is reported but not counted')
    }

    @Test
    void approvedExceptionSuppressesFindingUntilItExpires() {
        Map withException = SecurityGate.mergePolicy(policy, [exceptions: [[
            id: 'CVE-2026-0001', 'package': 'openssl', reason: 'not reachable', approvedBy: 'secteam',
            expires: '2026-12-31']]])
        Map r = SecurityGate.evaluate(withException, 'dev', image, 'OK', TODAY)
        assertEquals('UNSTABLE', r.decision, 'only HIGH warnings remain in dev')
        assertEquals(['CVE-2026-0001'], r.suppressed*.id)

        Map later = SecurityGate.evaluate(withException, 'dev', image, 'OK', '2027-01-01')
        assertEquals('FAIL', later.decision)
        assertEquals(1, later.expiredExceptions.size())
        assertTrue(later.reasons.any { it.contains('expired') })
    }

    @Test
    void exceptionMustMatchPackage() {
        Map wrongPkg = SecurityGate.mergePolicy(policy, [exceptions: [[
            id: 'CVE-2026-0001', 'package': 'not-openssl', reason: 'x', approvedBy: 'y', expires: '2030-01-01']]])
        assertEquals('FAIL', SecurityGate.evaluate(wrongPkg, 'dev', image, 'OK', TODAY).decision)
    }

    @Test
    void yamlDatesAreHandled() {
        Map p = loadYaml('''
            exceptions:
              - id: CVE-2026-0001
                reason: r
                approvedBy: a
                expires: 2026-12-31
        '''.stripIndent())
        assertTrue(p.exceptions[0].expires instanceof Date)
        Map r = SecurityGate.evaluate(SecurityGate.mergePolicy(policy, p), 'dev', image, 'OK', TODAY)
        assertEquals(['CVE-2026-0001'], r.suppressed*.id)
    }

    @Test
    void prodIsStricterThanDev() {
        List<Map> onlyHigh = image.findAll { it.severity == 'HIGH' }
        assertEquals('UNSTABLE', SecurityGate.evaluate(policy, 'dev', onlyHigh, 'OK', TODAY).decision)
        Map prod = SecurityGate.evaluate(policy, 'prod', onlyHigh, 'OK', TODAY)
        assertEquals('FAIL', prod.decision)
        assertEquals(2, prod.blocking.size())
    }

    @Test
    void misconfigurationThresholdsPerEnvironment() {
        assertEquals('UNSTABLE', SecurityGate.evaluate(policy, 'dev', fs, 'OK', TODAY).decision)
        Map prod = SecurityGate.evaluate(policy, 'prod', fs, 'OK', TODAY)
        assertEquals('FAIL', prod.decision)
        assertEquals(['AVD-DS-0002'], prod.blocking*.id)
    }

    @Test
    void anySecretFailsByDefault() {
        Map r = SecurityGate.evaluate(policy, 'dev', secrets, 'OK', TODAY)
        assertEquals('FAIL', r.decision)
        assertTrue(r.reasons[0].startsWith('1 secret(s) detected'))

        Map lenient = SecurityGate.mergePolicy(policy, [defaults: [secrets: [maxFindings: 1]]])
        assertEquals('UNSTABLE', SecurityGate.evaluate(lenient, 'dev', secrets, 'OK', TODAY).decision)
    }

    @Test
    void sonarQualityGateIsEnforced() {
        assertEquals('FAIL', SecurityGate.evaluate(policy, 'dev', [], 'ERROR', TODAY).decision)
        Map notRun = SecurityGate.evaluate(policy, 'dev', [], null, TODAY)
        assertEquals('UNSTABLE', notRun.decision)
        assertTrue(notRun.reasons.contains('SonarQube quality gate was not evaluated'))
        assertEquals('PASS', SecurityGate.evaluate(policy, 'dev', [], 'OK', TODAY).decision)
    }

    @Test
    void cleanReportsPass() {
        List<Map> clean = SecurityGate.parseTrivy(fixture('trivy-clean.json'), 'image') +
            SecurityGate.parseGitleaks(fixture('gitleaks-clean.json'))
        Map r = SecurityGate.evaluate(policy, 'prod', clean, 'OK', TODAY)
        assertEquals('PASS', r.decision)
        assertTrue(r.reasons.isEmpty())
    }

    @Test
    void mergeAppendsExceptionsAndOverridesScalars() {
        Map base = [defaults: [vulnerabilities: [failOn: ['CRITICAL'], ignoreUnfixed: true]],
                    exceptions: [[id: 'A']]]
        Map merged = SecurityGate.mergePolicy(base, [defaults: [vulnerabilities: [ignoreUnfixed: false]],
                                                     exceptions: [[id: 'B']]])
        assertEquals(['CRITICAL'], merged.defaults.vulnerabilities.failOn)
        assertFalse(merged.defaults.vulnerabilities.ignoreUnfixed as boolean)
        assertEquals(['A', 'B'], merged.exceptions*.id)
        assertEquals(1, base.exceptions.size(), 'inputs are not mutated')
    }

    @Test
    void markdownSummary() {
        Map r = SecurityGate.evaluate(policy, 'prod', image + fs + secrets, 'OK', TODAY)
        String md = SecurityGate.markdown(r)
        assertTrue(md.contains('Security gate: FAIL (prod)'))
        assertTrue(md.contains('| image |'))
        assertTrue(md.contains('`CVE-2026-0001`'))
        assertTrue(md.indexOf('SECRET') < md.indexOf('CVE-2026-0001'), 'secrets are listed first')
        assertTrue(SecurityGate.toJson(r).contains('"decision": "FAIL"'))
    }
}
