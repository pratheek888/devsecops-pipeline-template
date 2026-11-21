package io.github.pratheek888.devsecops

import org.junit.jupiter.api.Test

import static org.junit.jupiter.api.Assertions.assertEquals
import static org.junit.jupiter.api.Assertions.assertTrue
import static org.junit.jupiter.api.Assertions.assertFalse

class StepsTest extends LibraryTestBase {

    def runStep(String body) {
        File script = new File(workspace, 'Jenkinsfile')
        script.text = "@Library('devsecops') _\n${body}\n"
        return runScript(script.absolutePath)
    }

    @Test
    void secretScanUsesRedactedReportAndDefaultConfig() {
        runStep("secretScan()")
        String cmd = shell.find { it.startsWith('gitleaks') }
        assertTrue(cmd.contains('--redact'))
        assertTrue(cmd.contains('--report-path reports/gitleaks.json'))
        assertTrue(cmd.contains('--config reports/gitleaks-default.toml'), 'no .gitleaks.toml in repo')
        assertTrue(written['reports/gitleaks-default.toml'].contains('useDefault = true'))
        assertJobStatusSuccess()
    }

    @Test
    void secretScanRespectsRepoConfigAndFailsOnToolError() {
        new File(workspace, '.gitleaks.toml').text = '[extend]\nuseDefault = true\n'
        helper.addShMock(~/gitleaks.*/, '', 2)
        runStep("secretScan()")
        assertJobStatusFailure()
    }

    @Test
    void gatePassesCleanReports() {
        copyReport('trivy-clean.json', 'reports/trivy-image.json')
        copyReport('gitleaks-clean.json', 'reports/gitleaks.json')
        runStep("securityGate(environment: 'prod', sonarStatus: 'OK')")
        assertJobStatusSuccess()
        assertTrue(written['reports/security-gate.md'].contains('PASS (prod)'))
        assertTrue(written['reports/security-gate.json'].contains('"decision": "PASS"'))
    }

    @Test
    void gateFailsBuildOnCriticalVulnerability() {
        copyReport('trivy-image.json', 'reports/trivy-image.json')
        runStep("securityGate(environment: 'dev', sonarStatus: 'OK')")
        assertJobStatusFailure()
        assertTrue(written['reports/security-gate.md'].contains('CVE-2026-0001'))
    }

    @Test
    void gateMarksUnstableForWarningsOnly() {
        copyReport('trivy-fs.json', 'reports/trivy-fs.json')
        runStep("securityGate(environment: 'dev', sonarStatus: 'OK')")
        assertJobStatusUnstable()
    }

    @Test
    void repoPolicyExceptionsAreApplied() {
        copyReport('trivy-image.json', 'reports/trivy-image.json')
        new File(workspace, '.security-policy.yaml').text = '''
exceptions:
  - id: CVE-2026-0001
    package: openssl
    reason: "Not reachable from our code path; base image update scheduled"
    approvedBy: security-team
    expires: 2099-12-31
'''
        runStep("securityGate(environment: 'dev', sonarStatus: 'OK')")
        assertJobStatusUnstable()
        assertTrue(written['reports/security-gate.md'].contains('Suppressed by approved exceptions (1)'))
    }

    @Test
    void imagePublishPushesThenSignsByDigest() {
        def ref = runStep("return imagePublish(image: 'registry.example.com/team/payments-api:1a2b3c4d', " +
                          "vaultUrl: 'https://vault', vaultCredentialId: 'approle', registrySecretPath: 'secret/ci/reg')")
        assertEquals('registry.example.com/team/payments-api@sha256:abc123', ref)
        int push = shell.findIndexOf { it.startsWith('crane push') }
        int sign = shell.findIndexOf { it.startsWith('cosign sign') }
        int attest = shell.findIndexOf { it.startsWith('cosign attest') }
        assertTrue(push >= 0 && push < sign && sign < attest)
        assertTrue(shell[sign].contains('"$KEY"'), 'key comes from env, not interpolated')
        assertFalse(shell.any { it.contains('REGISTRY_PASSWORD') && !it.contains('"$REGISTRY_PASSWORD"') },
                    'password only referenced as a shell variable')
        assertEquals('registry.example.com/team/payments-api@sha256:abc123\n', written['reports/image-ref.txt'])
    }

    @Test
    void gitopsPromoteValidatesInputs() {
        runStep("gitopsPromote(repo: 'https://git/gitops.git', valuesFile: 'environments/dev/values.yaml')")
        assertJobStatusFailure()
    }

    @Test
    void gitopsPromoteRunsScriptWithEnvironment() {
        runStep("gitopsPromote(repo: 'https://git/gitops.git', valuesFile: 'environments/prod/values.yaml', " +
                "yamlPath: '.api.image.tag', tag: '1a2b3c4d', appName: 'api', environment: 'prod', " +
                "credentialsId: 'gitops-bot', openPullRequest: true)")
        assertJobStatusSuccess()
        assertTrue(ranCommand('sh reports/gitops-promote.sh'))
        assertTrue(written['reports/gitops-promote.sh'].contains('credential.helper'))
        def withEnv = helper.callStack.find { it.methodName == 'withEnv' }
        List envs = withEnv.args[0] as List
        assertTrue(envs.contains('OPEN_PR=true'))
        assertTrue(envs.contains('YAML_PATH=.api.image.tag'))
    }
}
