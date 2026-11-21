/**
 * Scan the built image tarball with Trivy (OS + language packages, secrets baked into layers)
 * and generate a CycloneDX SBOM with Syft. Both reports are archived and the SBOM is attested later.
 */
def call(Map args = [:]) {
    String tar = args.get('tarPath', 'image.tar')
    String report = args.get('report', 'reports/trivy-image.json')
    String sbom = args.get('sbom', 'reports/sbom.cdx.json')
    container(args.get('container', 'tools')) {
        sh 'mkdir -p reports'
        sh "trivy image --quiet --input ${tar} --scanners vuln,secret --format json --output ${report} --exit-code 0"
        sh "syft scan docker-archive:${tar} --output cyclonedx-json=${sbom} --quiet"
    }
    return [report: report, sbom: sbom]
}
