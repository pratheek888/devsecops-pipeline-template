import io.github.pratheek888.devsecops.SecurityGate

/**
 * Enforce the security policy across every scanner's report. Decides once, in one place:
 *   FAIL     -> error()     (pipeline stops, nothing is published)
 *   UNSTABLE -> unstable()  (build continues, flagged amber)
 *   PASS
 * Writes reports/security-gate.md (human summary) and reports/security-gate.json (machine-readable).
 *
 *   securityGate(environment: 'prod')
 */
def call(Map args = [:]) {
    String targetEnv = args.get('environment', 'dev')
    String policyFile = args.get('policyFile', '.security-policy.yaml')

    Map policy = readYaml(text: libraryResource('io/github/pratheek888/devsecops/default-policy.yaml'))
    if (fileExists(policyFile)) {
        policy = SecurityGate.mergePolicy(policy, readYaml(file: policyFile))
        echo "security policy: org defaults + ${policyFile}"
    }

    List<Map> findings = []
    Map<String, String> trivyReports = args.get('trivyReports', [
        'reports/trivy-fs.json'   : 'dependencies',
        'reports/trivy-image.json': 'image'
    ])
    for (String path in trivyReports.keySet()) {
        if (fileExists(path)) {
            findings.addAll(SecurityGate.parseTrivy(readFile(path), trivyReports[path]))
        }
    }
    String gitleaks = args.get('gitleaksReport', 'reports/gitleaks.json')
    if (fileExists(gitleaks)) {
        findings.addAll(SecurityGate.parseGitleaks(readFile(gitleaks)))
    }

    String sonar = args.containsKey('sonarStatus') ? args.sonarStatus : env.SONAR_QUALITY_GATE
    Map result = SecurityGate.evaluate(policy, targetEnv, findings, sonar, SecurityGate.today())

    writeFile file: 'reports/security-gate.md', text: SecurityGate.markdown(result)
    writeFile file: 'reports/security-gate.json', text: SecurityGate.toJson(result)
    echo SecurityGate.markdown(result, 10)

    String summary = result.reasons ? result.reasons.join('; ') : 'no blocking findings'
    if (result.decision == 'FAIL') {
        error "Security gate FAILED for ${targetEnv}: ${summary}"
    } else if (result.decision == 'UNSTABLE') {
        unstable "Security gate UNSTABLE for ${targetEnv}: ${summary}"
    }
    return result
}
