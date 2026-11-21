/**
 * Static analysis with SonarQube, then wait for the quality gate result (via the SonarQube webhook).
 * The status is stored in env.SONAR_QUALITY_GATE and enforced later by securityGate().
 *
 *   sastScan(projectKey: 'payments-api')
 */
def call(Map args = [:]) {
    String server = args.get('server', 'sonarqube')
    String projectKey = args.projectKey ?: error('sastScan: projectKey is required')
    String command = args.get('command',
        "mvn -B -q -DskipTests sonar:sonar -Dsonar.projectKey=${projectKey} " +
        "-Dsonar.qualitygate.wait=false")

    container(args.get('container', 'build')) {
        withSonarQubeEnv(server) {
            sh command
        }
    }
    timeout(time: args.get('timeoutMinutes', 10) as int, unit: 'MINUTES') {
        def gate = waitForQualityGate(abortPipeline: false)
        env.SONAR_QUALITY_GATE = gate.status
        echo "SonarQube quality gate: ${gate.status}"
        return gate.status
    }
}
