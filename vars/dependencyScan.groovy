/**
 * Software composition analysis + IaC checks on the source tree with Trivy:
 * vulnerable dependencies (pom.xml, package-lock.json, go.sum, ...) and misconfigurations
 * in Dockerfiles, Kubernetes manifests, Helm charts and Terraform.
 */
def call(Map args = [:]) {
    String report = args.get('report', 'reports/trivy-fs.json')
    String scanners = args.get('scanners', 'vuln,misconfig')
    container(args.get('container', 'tools')) {
        sh 'mkdir -p reports'
        sh "trivy fs --quiet --scanners ${scanners} --format json --output ${report} --exit-code 0 ${args.get('path', '.')}"
    }
    return report
}
