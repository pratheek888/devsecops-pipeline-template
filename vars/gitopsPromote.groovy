/**
 * Deploy by changing Git, not by running kubectl/helm from CI: bump the image tag in a GitOps
 * repository and let Argo CD reconcile. For protected environments, push a promote/* branch for review.
 *
 *   gitopsPromote(repo: 'https://github.com/org/gitops.git', valuesFile: 'environments/prod/values.yaml',
 *                 yamlPath: '.api.image.tag', tag: '1a2b3c4d', appName: 'api', environment: 'prod',
 *                 credentialsId: 'gitops-bot', openPullRequest: true)
 */
def call(Map args) {
    for (key in ['repo', 'valuesFile', 'yamlPath', 'tag', 'appName', 'credentialsId']) {
        if (!args[key]) {
            error "gitopsPromote: ${key} is required"
        }
    }
    writeFile file: 'reports/gitops-promote.sh',
              text: libraryResource('io/github/pratheek888/devsecops/gitops-promote.sh')
    container(args.get('container', 'tools')) {
        withCredentials([usernamePassword(credentialsId: args.credentialsId,
                                          usernameVariable: 'GIT_USER', passwordVariable: 'GIT_TOKEN')]) {
            withEnv([
                "GITOPS_REPO=${args.repo}",
                "GITOPS_BRANCH=${args.get('branch', 'main')}",
                "VALUES_FILE=${args.valuesFile}",
                "YAML_PATH=${args.yamlPath}",
                "IMAGE_TAG=${args.tag}",
                "APP_NAME=${args.appName}",
                "TARGET_ENV=${args.get('environment', 'dev')}",
                "OPEN_PR=${args.get('openPullRequest', false)}"
            ]) {
                sh 'sh reports/gitops-promote.sh'
            }
        }
    }
}
