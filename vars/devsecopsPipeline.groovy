import io.github.pratheek888.devsecops.SecurityGate

/**
 * Complete DevSecOps pipeline for a containerised service. A whole Jenkinsfile can be:
 *
 *   @Library('devsecops') _
 *   devsecopsPipeline(appName: 'payments-api', registry: 'registry.example.com/team')
 *
 * Stages: secret scan → build & test → SAST + dependency/IaC scan (parallel) → image build →
 * image scan + SBOM → security gate → publish + sign (release branch) → GitOps deploy.
 * See README for every option.
 */
def call(Map userConfig = [:]) {
    Map cfg = SecurityGate.mergePolicy(defaults(), userConfig)
    if (!cfg.appName || !cfg.registry) {
        error 'devsecopsPipeline: appName and registry are required'
    }
    String podYaml = libraryResource('io/github/pratheek888/devsecops/pod-template.yaml')
        .replace('${buildImage}', cfg.agent.buildImage as String)
        .replace('${toolsImage}', cfg.agent.toolsImage as String)
        .replace('${serviceAccount}', cfg.agent.serviceAccount as String)

    pipeline {
        agent {
            kubernetes {
                yaml podYaml
                defaultContainer 'tools'
            }
        }
        options {
            timestamps()
            timeout(time: cfg.timeoutMinutes as int, unit: 'MINUTES')
            buildDiscarder(logRotator(numToKeepStr: '30'))
            disableConcurrentBuilds()
        }
        environment {
            IMAGE_TAG = "${env.GIT_COMMIT ? env.GIT_COMMIT.take(8) : env.BUILD_NUMBER}"
            IMAGE = "${cfg.registry}/${cfg.appName}:${env.GIT_COMMIT ? env.GIT_COMMIT.take(8) : env.BUILD_NUMBER}"
        }
        stages {
            stage('Secret scan') {
                steps {
                    secretScan(logOpts: cfg.secretScanLogOpts)
                }
            }
            stage('Build & unit test') {
                steps {
                    container('build') {
                        sh cfg.buildCommand
                    }
                }
                post {
                    always {
                        junit allowEmptyResults: true, testResults: cfg.testResults
                    }
                }
            }
            stage('Code & dependency analysis') {
                parallel {
                    stage('SAST (SonarQube)') {
                        when { expression { cfg.sonar.enabled } }
                        steps {
                            sastScan(server: cfg.sonar.server, projectKey: cfg.sonar.projectKey ?: cfg.appName)
                        }
                    }
                    stage('SCA + IaC (Trivy)') {
                        steps {
                            dependencyScan()
                        }
                    }
                }
            }
            stage('Container image') {
                steps {
                    imageBuild(image: env.IMAGE, context: cfg.context, dockerfile: cfg.dockerfile)
                    imageScan()
                }
            }
            stage('Security gate') {
                steps {
                    securityGate(environment: cfg.environment, policyFile: cfg.policyFile,
                                 sonarStatus: cfg.sonar.enabled ? env.SONAR_QUALITY_GATE : 'OK')
                }
            }
            stage('Publish & sign') {
                when { branch cfg.releaseBranch }
                steps {
                    script {
                        env.IMAGE_REF = imagePublish(
                            image: env.IMAGE,
                            vaultUrl: cfg.vault.url,
                            vaultCredentialId: cfg.vault.credentialId,
                            registrySecretPath: cfg.vault.registrySecretPath,
                            cosignKey: cfg.vault.cosignKey)
                    }
                }
            }
            stage('Deploy (GitOps)') {
                when {
                    allOf {
                        branch cfg.releaseBranch
                        expression { cfg.gitops.enabled }
                    }
                }
                steps {
                    gitopsPromote(
                        repo: cfg.gitops.repo,
                        branch: cfg.gitops.branch,
                        valuesFile: cfg.gitops.valuesFile,
                        yamlPath: cfg.gitops.yamlPath,
                        tag: env.IMAGE_TAG,
                        appName: cfg.appName,
                        environment: cfg.environment,
                        credentialsId: cfg.gitops.credentialsId,
                        openPullRequest: cfg.gitops.openPullRequest)
                }
            }
        }
        post {
            always {
                archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true, fingerprint: true
            }
        }
    }
}

/** Defaults for every option; anything passed to devsecopsPipeline(...) is deep-merged over these. */
Map defaults() {
    return [
        appName          : null,
        registry         : null,
        environment      : 'dev',
        releaseBranch    : 'main',
        buildCommand     : 'mvn -B verify',
        testResults      : '**/target/surefire-reports/*.xml',
        context          : '.',
        dockerfile       : 'Dockerfile',
        policyFile       : '.security-policy.yaml',
        secretScanLogOpts: null,
        timeoutMinutes   : 45,
        agent            : [
            buildImage    : 'maven:3.9-eclipse-temurin-21',
            toolsImage    : 'ghcr.io/pratheek888/devsecops-tools:latest',
            serviceAccount: 'jenkins-agent'
        ],
        sonar            : [enabled: true, server: 'sonarqube', projectKey: null],
        vault            : [
            url               : 'https://vault.example.com',
            credentialId      : 'jenkins-vault-approle',
            registrySecretPath: 'secret/ci/registry',
            cosignKey         : 'cosign'
        ],
        gitops           : [
            enabled        : false,
            repo           : null,
            branch         : 'main',
            valuesFile     : null,
            yamlPath       : null,
            credentialsId  : 'gitops-bot',
            openPullRequest: false
        ]
    ]
}
