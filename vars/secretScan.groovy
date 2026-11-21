/**
 * Scan the repository and its git history for committed secrets with Gitleaks.
 * The report is redacted: secret values never reach the build log or archived artifacts.
 *
 *   secretScan()                                  // full history
 *   secretScan(logOpts: 'origin/main..HEAD')      // only commits new on this branch
 */
def call(Map args = [:]) {
    String report = args.get('report', 'reports/gitleaks.json')
    String configFlag = ''
    if (!fileExists('.gitleaks.toml')) {
        writeFile file: 'reports/gitleaks-default.toml',
                  text: libraryResource('io/github/pratheek888/devsecops/gitleaks.toml')
        configFlag = ' --config reports/gitleaks-default.toml'
    }
    String logOpts = args.logOpts ? " --log-opts='${args.logOpts}'" : ''

    container(args.get('container', 'tools')) {
        sh 'mkdir -p reports'
        // Exit codes: 0 = clean, 1 = leaks found (the security gate decides), anything else = tool error.
        int rc = sh(returnStatus: true,
                    script: "gitleaks git --redact --no-banner --exit-code 1 --report-format json " +
                            "--report-path ${report}${configFlag}${logOpts} .")
        if (rc > 1) {
            error "gitleaks failed with exit code ${rc}"
        }
        echo(rc == 1 ? 'gitleaks: potential secrets found (see security gate)' : 'gitleaks: no secrets found')
    }
    return report
}
