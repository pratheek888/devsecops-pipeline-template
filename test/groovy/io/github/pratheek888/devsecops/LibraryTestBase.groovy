package io.github.pratheek888.devsecops

import com.lesfurets.jenkins.unit.declarative.DeclarativePipelineTest
import org.junit.jupiter.api.BeforeEach
import org.yaml.snakeyaml.LoaderOptions
import org.yaml.snakeyaml.Yaml
import org.yaml.snakeyaml.constructor.SafeConstructor

import java.nio.file.Files

import static com.lesfurets.jenkins.unit.global.lib.LibraryConfiguration.library
import static com.lesfurets.jenkins.unit.global.lib.ProjectSource.projectSource

/**
 * Loads this repository as the 'devsecops' shared library and fakes the Jenkins steps it uses.
 * A real temp directory acts as the workspace so fileExists/readFile/writeFile behave like Jenkins.
 */
abstract class LibraryTestBase extends DeclarativePipelineTest {

    File workspace
    Map<String, String> written = [:]
    List<String> shell = []

    @Override
    @BeforeEach
    void setUp() throws Exception {
        super.setUp()
        helper.registerSharedLibrary(library()
            .name('devsecops')
            .defaultVersion('<notNeeded>')
            .allowOverride(true)
            .implicit(false)
            .targetPath('<notNeeded>')
            .retriever(projectSource())
            .build())

        workspace = Files.createTempDirectory('ws').toFile()
        new File(workspace, 'reports').mkdirs()
        binding.setVariable('env', [BRANCH_NAME: 'main', GIT_COMMIT: '1a2b3c4d5e6f7a8b9c0d', BUILD_NUMBER: '42'])

        Yaml yaml = new Yaml(new SafeConstructor(new LoaderOptions()))
        helper.registerAllowedMethod('fileExists', [String]) { String p -> new File(workspace, p).exists() }
        helper.registerAllowedMethod('readFile', [String]) { String p -> new File(workspace, p).text }
        helper.registerAllowedMethod('writeFile', [Map]) { Map a ->
            written[a.file as String] = a.text as String
            File f = new File(workspace, a.file as String)
            f.parentFile.mkdirs()
            f.text = a.text
        }
        helper.registerAllowedMethod('readYaml', [Map]) { Map a ->
            a.text != null ? yaml.load(a.text as String) : yaml.load(new File(workspace, a.file as String).text)
        }
        helper.registerAllowedMethod('withSonarQubeEnv', [String, Closure]) { String s, Closure c -> c.call() }
        helper.registerAllowedMethod('waitForQualityGate', [Map]) { Map a -> [status: 'OK'] }
        helper.registerAllowedMethod('withVault', [Map, Closure]) { Map a, Closure c -> c.call() }
        // Credentials bindings are exercised for real in the GitOps script test; here just run the body.
        helper.registerAllowedMethod('withCredentials', [List, Closure]) { List l, Closure c -> c.call() }
        // Like Jenkins: error() aborts the run (JenkinsPipelineUnit's default only sets the status).
        helper.registerAllowedMethod('error', [String]) { String msg ->
            updateBuildStatus('FAILURE')
            throw new PipelineAborted(msg)
        }
        helper.registerAllowedMethod('junit', [Map], null)
        helper.registerAllowedMethod('timestamps', [], null)
        helper.registerAllowedMethod('disableConcurrentBuilds', [], null)
        helper.registerAllowedMethod('logRotator', [Map], null)
        helper.registerAllowedMethod('buildDiscarder', [Object], null)

        // Record every shell command; individual tests add specific mocks on top.
        helper.addShMock(~/(?s).*/) { String script ->
            shell << script
            return [stdout: '', exitValue: 0]
        }
        helper.addShMock(~/(?s)crane push.*/) { String script ->
            shell << script
            return [stdout: 'registry.example.com/team/payments-api@sha256:abc123\n', exitValue: 0]
        }
    }

    void copyReport(String fixture, String target) {
        File dest = new File(workspace, target)
        dest.parentFile.mkdirs()
        dest.text = LibraryTestBase.getResourceAsStream("/reports/${fixture}").getText('UTF-8')
    }

    /** Make the scanner steps "produce" these reports when their commands run. */
    void scannersProduce(Map<String, String> reports) {
        helper.addShMock(~/(?s)(?:trivy fs|trivy image|gitleaks git).*/) { String script ->
            shell << script
            reports.each { String cmdPrefix, String fixture ->
                if (script.startsWith(cmdPrefix)) {
                    String target = cmdPrefix == 'gitleaks git' ? 'reports/gitleaks.json' :
                        (cmdPrefix == 'trivy fs' ? 'reports/trivy-fs.json' : 'reports/trivy-image.json')
                    copyReport(fixture, target)
                }
            }
            return [stdout: '', exitValue: script.startsWith('gitleaks') && reports['gitleaks git'] == 'gitleaks.json' ? 1 : 0]
        }
    }

    /** Run a pipeline script; an error() abort is recorded in the job status, like Jenkins does. */
    def runPipeline(String path) {
        try {
            return runScript(path)
        } catch (PipelineAborted ignored) {
            return null
        }
    }

    boolean ranCommand(String prefix) {
        return shell.any { it.startsWith(prefix) }
    }
}

class PipelineAborted extends RuntimeException {
    PipelineAborted(String message) {
        super(message)
    }
}
