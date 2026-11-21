/**
 * Push the gate-approved image, sign it and attach the SBOM as a signed attestation.
 *
 * - Registry credentials come from HashiCorp Vault (KV v2) for the duration of this step only.
 * - The signing key never leaves Vault: cosign uses the Vault Transit engine (hashivault://<key>).
 * - Everything is signed by digest, not tag, so what was scanned is exactly what gets deployed.
 *
 *   def ref = imagePublish(image: 'registry.example.com/payments-api:1a2b3c4d',
 *                          vaultUrl: 'https://vault.example.com', vaultCredentialId: 'jenkins-approle',
 *                          registrySecretPath: 'secret/ci/registry', cosignKey: 'cosign')
 */
def call(Map args) {
    String image = args.image ?: error('imagePublish: image is required')
    String tar = args.get('tarPath', 'image.tar')
    String sbom = args.get('sbom', 'reports/sbom.cdx.json')
    String registry = image.tokenize('/')[0]

    Map vaultConfig = [vaultUrl: args.vaultUrl, vaultCredentialId: args.vaultCredentialId, engineVersion: 2]
    List vaultSecrets = [[path: args.registrySecretPath, secretValues: [
        [envVar: 'REGISTRY_USER', vaultKey: 'username'],
        [envVar: 'REGISTRY_PASSWORD', vaultKey: 'password']
    ]]]

    String digestRef = null
    container(args.get('container', 'tools')) {
        withVault(configuration: vaultConfig, vaultSecrets: vaultSecrets) {
            withEnv(["REGISTRY=${registry}", "IMAGE=${image}", "TAR=${tar}"]) {
                // Single-quoted: secrets are expanded by the shell, never interpolated by Groovy into the log.
                sh 'printf %s "$REGISTRY_PASSWORD" | crane auth login "$REGISTRY" -u "$REGISTRY_USER" --password-stdin'
                digestRef = sh(returnStdout: true, script: 'crane push "$TAR" "$IMAGE"').trim()
            }
        }
        withCredentials([[$class: 'VaultTokenCredentialBinding', credentialsId: args.vaultCredentialId,
                          vaultAddr: args.vaultUrl]]) {
            withEnv(["REF=${digestRef}", "KEY=hashivault://${args.get('cosignKey', 'cosign')}", "SBOM=${sbom}"]) {
                sh 'cosign sign --yes --key "$KEY" "$REF"'
                sh 'cosign attest --yes --key "$KEY" --type cyclonedx --predicate "$SBOM" "$REF"'
            }
        }
    }
    writeFile file: 'reports/image-ref.txt', text: digestRef + '\n'
    echo "published and signed ${digestRef}"
    return digestRef
}
