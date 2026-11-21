package io.github.pratheek888.devsecops.cli

import io.github.pratheek888.devsecops.SecurityGate
import org.yaml.snakeyaml.LoaderOptions
import org.yaml.snakeyaml.Yaml
import org.yaml.snakeyaml.constructor.SafeConstructor

/**
 * Run the security gate outside Jenkins (GitHub Actions, GitLab, a laptop) with the same policy engine.
 *
 *   ./gradlew -q securityGate --args="--env prod --trivy dependencies=reports/trivy-fs.json \
 *       --trivy image=reports/trivy-image.json --gitleaks reports/gitleaks.json --out reports"
 *
 * Exit code: 0 PASS, 0 UNSTABLE (unless --strict), 1 FAIL.
 */
class GateCli {

    static void main(String[] argv) {
        Map opts = [env: 'dev', trivy: [:], gitleaks: null, policy: '.security-policy.yaml', out: 'reports',
                    sonar: null, strict: false, workdir: System.getProperty('user.dir')]
        List<String> args = argv as List
        for (int i = 0; i < args.size(); i++) {
            String a = args[i]
            switch (a) {
                case '--env': opts.env = args[++i]; break
                case '--trivy':
                    String spec = args[++i]
                    List parts = spec.contains('=') ? spec.split('=', 2) as List : ['trivy', spec]
                    opts.trivy[parts[0]] = parts[1]
                    break
                case '--gitleaks': opts.gitleaks = args[++i]; break
                case '--policy': opts.policy = args[++i]; break
                case '--sonar': opts.sonar = args[++i]; break
                case '--out': opts.out = args[++i]; break
                case '--dir': opts.workdir = args[++i]; break
                case '--strict': opts.strict = true; break
                default:
                    System.err.println("unknown argument: ${a}")
                    System.exit(2)
            }
        }
        File base = new File(opts.workdir as String)
        Closure<File> f = { String p -> new File(p).isAbsolute() ? new File(p) : new File(base, p) }

        Yaml yaml = new Yaml(new SafeConstructor(new LoaderOptions()))
        Map policy = yaml.load(GateCli.getResourceAsStream('/io/github/pratheek888/devsecops/default-policy.yaml')
            .getText('UTF-8')) as Map
        File repoPolicy = f(opts.policy as String)
        if (repoPolicy.exists()) {
            policy = SecurityGate.mergePolicy(policy, (yaml.load(repoPolicy.text) ?: [:]) as Map)
        }

        List<Map> findings = []
        (opts.trivy as Map).each { String source, String path ->
            File report = f(path)
            if (report.exists()) {
                findings.addAll(SecurityGate.parseTrivy(report.text, source))
            } else {
                System.err.println("warning: ${path} not found")
            }
        }
        if (opts.gitleaks && f(opts.gitleaks as String).exists()) {
            findings.addAll(SecurityGate.parseGitleaks(f(opts.gitleaks as String).text))
        }

        // Outside Jenkins there is usually no SonarQube webhook; only enforce it if a status is given.
        if (opts.sonar == null) {
            policy = SecurityGate.mergePolicy(policy, [defaults: [sast: [requireQualityGate: false]]])
        }
        Map result = SecurityGate.evaluate(policy, opts.env as String, findings, opts.sonar as String,
                                           SecurityGate.today())
        File out = f(opts.out as String)
        out.mkdirs()
        new File(out, 'security-gate.md').text = SecurityGate.markdown(result)
        new File(out, 'security-gate.json').text = SecurityGate.toJson(result)

        println SecurityGate.markdown(result)
        String summaryFile = System.getenv('GITHUB_STEP_SUMMARY')
        if (summaryFile) {
            new File(summaryFile) << SecurityGate.markdown(result)
        }
        boolean failed = result.decision == 'FAIL' || (opts.strict && result.decision == 'UNSTABLE')
        System.exit(failed ? 1 : 0)
    }
}
