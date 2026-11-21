/**
 * Build the container image with Kaniko (no Docker daemon) into a local tarball.
 * Nothing is pushed here: the image is only published after it passes the security gate.
 *
 *   imageBuild(image: 'registry.example.com/payments-api:1a2b3c4d')
 */
def call(Map args) {
    String image = args.image ?: error('imageBuild: image is required')
    String tar = args.get('tarPath', 'image.tar')
    List<String> flags = [
        "--context=${args.get('context', '.')}",
        "--dockerfile=${args.get('dockerfile', 'Dockerfile')}",
        "--destination=${image}",
        '--no-push',
        "--tar-path=${tar}",
        '--reproducible',
        '--snapshot-mode=redo'
    ]
    for (arg in (args.buildArgs ?: [:])) {
        flags << "--build-arg=${arg.key}=${arg.value}"
    }
    container(args.get('container', 'kaniko')) {
        sh "/kaniko/executor ${flags.join(' ')}"
    }
    return tar
}
