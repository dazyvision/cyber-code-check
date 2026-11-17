import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cyber.__main__ import main
from cyber.advisories import audit_lockfile, build_inventory
from cyber.advisory_report import advisory_exit_code, render_advisory_html, render_advisory_markdown, write_advisory_report


def sample(complete=True, findings=True):
    return {
        'kind': 'dependency_advisories', 'generated_at': '2026-11-17T00:00:00+00:00',
        'inventory': {'lockfile_sha256': 'a'*64, 'packages': [
            {'name': 'example', 'version': '1.0.0', 'paths': ['node_modules/example'], 'dev': False}]},
        'coverage': {'complete': complete, 'queried_packages': int(complete)},
        'findings': [{'package': 'example', 'version': '1.0.0', 'paths': ['node_modules/example'],
                      'advisory_id': 'GHSA-example', 'modified': '2026-11-01T00:00:00Z',
                      'source_url': 'https://osv.dev/vulnerability/GHSA-example'}] if findings else [],
        'notices': [] if complete else [{'code': 'QUERY_FAILED', 'message': 'Source indisponible'}],
    }


class AdvisoryReportTests(unittest.TestCase):
    def test_global_result_and_notice_limits_remain_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            lock = Path(tmp)/'package-lock.json'
            lock.write_text(json.dumps({'lockfileVersion': 3, 'packages': {'node_modules/example': {
                'version': '1.0.0', 'resolved': 'https://registry.npmjs.org/example/-/example-1.0.0.tgz'}}}))
            def response(payload):
                return {'results': [{'vulns': [{'id': 'GHSA-a'}, {'id': 'GHSA-b'}]}]}
            with patch('cyber.advisories.MAX_FINDINGS', 1):
                report = audit_lockfile(lock, online=True, transport=response)
            self.assertEqual(len(report['findings']), 1)
            self.assertFalse(report['coverage']['complete'])
            self.assertEqual(report['coverage']['queried_packages'], 0)
            self.assertIn('OSV_FINDING_LIMIT', [n['code'] for n in report['notices']])
            lock.write_text(json.dumps({'lockfileVersion': 3, 'packages': {str(i): {} for i in range(20)}}))
            with patch('cyber.advisories.MAX_NOTICES', 2):
                inventory = build_inventory(lock)
            self.assertFalse(inventory['complete'])
            self.assertEqual(len(inventory['notices']), 3)
            self.assertEqual(inventory['notices'][-1]['code'], 'NOTICE_LIMIT')

    def test_inventory_only_does_not_audit_or_write(self):
        inventory = {'packages': [], 'notices': [{'code': 'EXCLUDED'}], 'complete': False}
        with patch('cyber.advisories.build_inventory', return_value=inventory) as build:
            with patch('cyber.advisories.audit_lockfile') as audit:
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    code = main(['advisories', '/some/package-lock.json', '--inventory-only'])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out.getvalue()), inventory)
        audit.assert_not_called()
        build.assert_called_once()

    def test_incomplete_has_priority_over_findings_and_none_policy(self):
        self.assertEqual(advisory_exit_code(sample(False), 'none'), 2)
        self.assertEqual(advisory_exit_code(sample(False, False)), 2)
        self.assertEqual(advisory_exit_code(sample()), 1)
        self.assertEqual(advisory_exit_code(sample(), 'none'), 0)
        self.assertEqual(advisory_exit_code(sample(True, False)), 0)

    def test_untrusted_text_escaped_and_scope_preserved(self):
        report = sample(False)
        report['findings'][0]['package'] = '<script>evil()</script>'
        report['notices'][0]['message'] = '<img src=x onerror=evil()>'
        html = render_advisory_html(report)
        self.assertNotIn('<script>', html)
        self.assertNotIn('<img src=x', html)
        self.assertIn('&lt;script&gt;', html)
        self.assertIn('Consultation incomplète', html)
        self.assertIn("default-src 'none'", html)
        self.assertNotIn('<script>', render_advisory_markdown(report))

    def test_output_is_outside_source_and_does_not_follow_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source = root/'source'; source.mkdir()
            lock = source/'package-lock.json'; lock.write_text('{}')
            with self.assertRaises(ValueError):
                write_advisory_report(sample(), source/'out', lockfile=lock)
            output = root/'output'; output.mkdir()
            (output/'report.json').symlink_to(lock)
            with self.assertRaises(ValueError):
                write_advisory_report(sample(), output, lockfile=lock)
            self.assertEqual(lock.read_text(), '{}')
            (output/'report.json').unlink()
            write_advisory_report(sample(), output, lockfile=lock)
            result = json.loads((output/'report.json').read_text())
            self.assertEqual(result['findings'][0]['advisory_id'], 'GHSA-example')
            self.assertTrue(result['limitations'])

    def test_cli_writes_incomplete_report_and_returns_two(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source = root/'source'; source.mkdir()
            lock = source/'package-lock.json'; lock.write_text('{}')
            out = root/'report'
            with patch('cyber.advisories.audit_lockfile', return_value=sample(False)) as audit:
                with contextlib.redirect_stdout(io.StringIO()):
                    code = main(['advisories', str(lock), '--online', '--output', str(out), '--fail-on', 'none'])
            self.assertEqual(code, 2)
            audit.assert_called_once_with(lock, online=True)
            self.assertTrue((out/'index.html').is_file())


if __name__ == '__main__':
    unittest.main()
