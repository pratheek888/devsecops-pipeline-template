package io.github.pratheek888.devsecops

import org.junit.jupiter.api.Test

import static org.junit.jupiter.api.Assertions.assertEquals
import static org.junit.jupiter.api.Assertions.assertTrue
import static org.junit.jupiter.api.Assertions.assertFalse

/** Runs examples/Jenkinsfile end to end against the library. */
class DevsecopsPipelineTest extends LibraryTestBase {

    static final List<String> SCANNERS_IN_ORDER = [
        'gitleaks git', 'mvn -B verify', 'trivy fs', '/kaniko/executor', 'trivy image', 'syft scan'
    ]

    def runExample() {
        return runScript('examples/Jenkinsfile')
    }

    @Test
    void releaseBranchRunsEveryStageInOrder() {
        scannersProduce(['trivy image': 'trivy-clean.json', 'gitleaks git': 'gitleaks-clean.json'])
        runExample()
        assertJobStatusSuccess()

        List<Integer> positions = SCANNERS_IN_ORDER.collect { p -> shell.findIndexOf { it.startsWith(p) } }
        assertFalse(positions.contains(-1), "missing commands: ${SCANNERS_IN_ORDER} -> ${positions}")
        assertEquals(positions.sort(false), positions, 'stages ran in the expected order')

        assertTrue(ranCommand('mvn -B -q -DskipTests sonar:sonar -Dsonar.projectKey=payments-api'))
        assertTrue(ranCommand('crane push'))
        assertTrue(ranCommand('cosign sign'))
        assertTrue(ranCommand('sh reports/gitops-promote.sh'))

        String kaniko = shell.find { it.startsWith('/kaniko/executor') }
        assertTrue(kaniko.contains('--destination=registry.example.com/team/payments-api:1a2b3c4d'))
        assertTrue(kaniko.contains('--no-push'), 'image is only pushed after the gate')
    }

    @Test
    void featureBranchesAreScannedButNotPublished() {
        binding.getVariable('env').BRANCH_NAME = 'feature/new-endpoint'
        scannersProduce(['trivy image': 'trivy-clean.json'])
        runExample()
        assertJobStatusSuccess()
        assertTrue(ranCommand('trivy image'))
        assertFalse(ranCommand('crane push'))
        assertFalse(ranCommand('cosign'))
        assertFalse(ranCommand('sh reports/gitops-promote.sh'))
    }

    @Test
    void criticalVulnerabilityStopsThePipelineBeforePublishing() {
        scannersProduce(['trivy image': 'trivy-image.json'])
        runExample()
        assertJobStatusFailure()
        assertTrue(ranCommand('trivy image'))
        assertFalse(ranCommand('crane push'), 'nothing is published after a failed gate')
        assertFalse(ranCommand('sh reports/gitops-promote.sh'))
    }

    @Test
    void leakedSecretStopsThePipeline() {
        scannersProduce(['trivy image': 'trivy-clean.json', 'gitleaks git': 'gitleaks.json'])
        runExample()
        assertJobStatusFailure()
        assertFalse(ranCommand('crane push'))
    }

    @Test
    void reportsAreAlwaysArchived() {
        scannersProduce(['trivy image': 'trivy-image.json'])
        runExample()
        assertTrue(helper.callStack.any { it.methodName == 'archiveArtifacts' })
    }
}
