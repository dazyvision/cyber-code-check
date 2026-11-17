import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cyber.advisories import _NoRedirect, _transport, audit_lockfile, build_inventory


def package(name='demo', version='1.2.3', **extra):
    value = {'version': version, 'resolved': f'https://registry.npmjs.org/{name}/-/{name.rsplit("/", 1)[-1]}-{version}.tgz'}
    value.update(extra)
    return value


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'package-lock.json'

    def write(self, packages, version=3):
        self.path.write_text(json.dumps({'lockfileVersion': version, 'packages': {'': {'name': 'private-application'}, **packages}}))
        return self.path

    def test_groups_versions_and_preserves_paths_and_dev_union(self):
        path = self.write({'node_modules/demo': package(dev=True),
                           'node_modules/parent/node_modules/demo': package(dev=False),
                           'node_modules/@scope/item': package('@scope/item', '2.0.0-beta.2+build.1', dev=True)})
        inv = build_inventory(path)
        self.assertTrue(inv['complete'])
        self.assertEqual(inv['lockfile_sha256'], hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(len(inv['packages']), 2)
        demo = next(p for p in inv['packages'] if p['name'] == 'demo')
        self.assertFalse(demo['dev'])
        self.assertEqual(demo['paths'], ['node_modules/demo', 'node_modules/parent/node_modules/demo'])

    def test_v2_optional_dependency_is_included(self):
        inv = build_inventory(self.write({'node_modules/demo': package(optional=True)}, version=2))
        self.assertTrue(inv['complete'])
        self.assertEqual(inv['packages'][0]['name'], 'demo')

    def test_alias_private_missing_and_mismatched_urls_are_excluded(self):
        entries = {
            'node_modules/demo': package(),
            'node_modules/private': package('private', resolved='https://token@private.example/private.tgz'),
            'node_modules/missing': {'version': '1.0.0'},
            'node_modules/alias': package(name='demo'),
            'node_modules/explicit-alias': {**package('demo'), 'name': 'demo'},
            'node_modules/bad-version': package('bad-version', resolved='https://registry.npmjs.org/bad-version/-/bad-version-2.0.0.tgz'),
            'node_modules/local': {'version': '1.0.0', 'link': True, 'resolved': '../private'},
        }
        # Explicit name aliases cannot be made through the fixture's name argument.
        entries['node_modules/explicit-alias'] = {**package('demo'), 'name': 'demo'}
        inv = build_inventory(self.write(entries))
        self.assertFalse(inv['complete'])
        self.assertEqual([p['name'] for p in inv['packages']], ['demo'])
        self.assertIn('ALIAS_EXCLUDED', {n['code'] for n in inv['notices']})
        self.assertNotIn('token', json.dumps(inv))

    def test_host_credentials_queries_fragments_and_path_traversal_not_sent(self):
        bad_urls = [
            'http://registry.npmjs.org/demo/-/demo-1.2.3.tgz',
            'https://registry.npmjs.org.evil.example/demo/-/demo-1.2.3.tgz',
            'https://a:b@registry.npmjs.org/demo/-/demo-1.2.3.tgz',
            'https://registry.npmjs.org:443/demo/-/demo-1.2.3.tgz',
            'https://registry.npmjs.org/demo/-/demo-1.2.3.tgz?secret=x',
            'https://registry.npmjs.org/demo/-/demo-1.2.3.tgz#x',
            'https://registry.npmjs.org/demo/%2e%2e/-/demo-1.2.3.tgz',
        ]
        for url in bad_urls:
            with self.subTest(url=url):
                inv = build_inventory(self.write({'node_modules/demo': package(resolved=url)}))
                self.assertFalse(inv['packages'])
                self.assertFalse(inv['complete'])

    def test_encoded_scope_is_allowed_but_path_identity_must_match(self):
        inv = build_inventory(self.write({'node_modules/@scope/item': package('@scope/item', resolved='https://registry.npmjs.org/@scope%2Fitem/-/item-1.2.3.tgz')}))
        self.assertTrue(inv['complete'])
        for path in ('../node_modules/demo', 'node_modules/../demo', 'node_modules/demo/child', 'node_modules/demo\\secret'):
            inv = build_inventory(self.write({path: package()}))
            self.assertFalse(inv['complete'])
            self.assertFalse(inv['packages'])

    def test_invalid_versions_never_query(self):
        for version in ('^1.2.3', 'https://evil', 'npm:demo@1.2.3', '1', '1.2.3\nsecret', None, True):
            inv = build_inventory(self.write({'node_modules/demo': package(version=version)}))
            self.assertFalse(inv['complete'])
            self.assertFalse(inv['packages'])

    def test_no_public_packages_is_incomplete(self):
        inv = build_inventory(self.write({}))
        self.assertFalse(inv['complete'])
        self.assertIn('NO_PUBLIC_PACKAGES', {n['code'] for n in inv['notices']})

    def test_bad_json_duplicate_keys_format_and_depth_rejected(self):
        for text in ('not json', '{"lockfileVersion":3,"lockfileVersion":2,"packages":{}}',
                     '[1]', '{"lockfileVersion":true,"packages":{}}',
                     '{"lockfileVersion":1,"packages":{}}', '[' * 2000 + ']' * 2000):
            self.path.write_text(text)
            with self.subTest(text=text[:30]), self.assertRaises(ValueError):
                build_inventory(self.path)

    def test_symlink_and_fifo_are_rejected_without_blocking(self):
        target = self.write({'node_modules/demo': package()})
        alias = self.path.parent / 'alias.json'
        alias.symlink_to(target)
        with self.assertRaises(ValueError):
            build_inventory(alias)
        fifo = self.path.parent / 'pipe.json'
        os.mkfifo(fifo)
        with self.assertRaises(ValueError):
            build_inventory(fifo)

    def test_file_and_package_count_limits(self):
        self.path.write_bytes(b'x' * 20)
        with patch('cyber.advisories.MAX_LOCKFILE_BYTES', 10), self.assertRaises(ValueError):
            build_inventory(self.path)
        self.write({'node_modules/demo': package(), 'node_modules/other': package('other')})
        with patch('cyber.advisories.MAX_PACKAGES', 1), self.assertRaises(ValueError):
            build_inventory(self.path)


class AuditTests(unittest.TestCase):
    write = InventoryTests.write

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'package-lock.json'
        self.write({'node_modules/demo': package()})

    def test_network_requires_explicit_opt_in_even_with_transport(self):
        def forbidden(payload):
            raise AssertionError('network used')
        with self.assertRaises(ValueError):
            audit_lockfile(self.path, transport=forbidden)

    def test_only_public_package_identity_transmitted_and_no_source_executed(self):
        sentinel = self.path.parent / 'EXECUTED'
        self.write({'node_modules/demo': package(),
                    'node_modules/private': {'version': '1.0.0', 'resolved': 'file:secret'}})
        before = self.path.read_bytes()
        sent = []
        def fake(payload):
            sent.append(payload)
            return {'results': [{}]}
        report = audit_lockfile(self.path, online=True, transport=fake)
        self.assertEqual(sent, [{'queries': [{'package': {'name': 'demo', 'ecosystem': 'npm'}, 'version': '1.2.3'}]}])
        self.assertEqual(self.path.read_bytes(), before)
        self.assertFalse(sentinel.exists())
        self.assertFalse(report['coverage']['complete'])
        self.assertEqual(report['coverage']['queried_packages'], 1)

    def test_no_advisories_is_complete_only_after_valid_response(self):
        report = audit_lockfile(self.path, online=True, transport=lambda p: {'results': [{}]})
        self.assertTrue(report['coverage']['complete'])
        self.assertEqual(report['findings'], [])

    def test_invalid_response_or_failure_never_becomes_clean(self):
        for response in (None, [], {}, {'results': []}, {'results': [{}, {}]}, {'results': [{'error': 'x'}]}, {'results': [{'vulns': None}]}, {'results': [None]}):
            with self.subTest(response=response):
                report = audit_lockfile(self.path, online=True, transport=lambda p: response)
                self.assertFalse(report['coverage']['complete'])
                self.assertEqual(report['coverage']['queried_packages'], 0)
        def fail(payload):
            raise OSError('secret credential must not be in report')
        report = audit_lockfile(self.path, online=True, transport=fail)
        self.assertFalse(report['coverage']['complete'])
        self.assertNotIn('secret credential', json.dumps(report))

    def test_pagination_queries_only_pending_packages(self):
        self.write({'node_modules/demo': package(), 'node_modules/other': package('other')})
        sent = []
        responses = [
            {'results': [{'vulns': [{'id': 'GHSA-first', 'modified': '2026-11-17T10:00:00Z'}], 'next_page_token': 'page2'}, {}]},
            {'results': [{'vulns': [{'id': 'GHSA-second'}]}]},
        ]
        def fake(payload):
            sent.append(payload)
            return responses.pop(0)
        report = audit_lockfile(self.path, online=True, transport=fake)
        self.assertTrue(report['coverage']['complete'])
        self.assertEqual(report['coverage']['queried_packages'], 2)
        self.assertEqual(len(sent[1]['queries']), 1)
        self.assertEqual(sent[1]['queries'][0]['package']['name'], 'demo')
        self.assertEqual(sent[1]['queries'][0]['page_token'], 'page2')
        self.assertEqual({f['advisory_id'] for f in report['findings']}, {'GHSA-first', 'GHSA-second'})

    def test_repeated_or_excessive_pagination_preserves_findings(self):
        def repeat(payload):
            return {'results': [{'vulns': [{'id': 'GHSA-safe'}], 'next_page_token': 'repeat'}]}
        report = audit_lockfile(self.path, online=True, transport=repeat)
        self.assertFalse(report['coverage']['complete'])
        self.assertEqual(len(report['findings']), 1)
        counter = iter(range(100))
        def pages(payload):
            return {'results': [{'vulns': [{'id': 'GHSA-safe'}], 'next_page_token': str(next(counter))}]}
        with patch('cyber.advisories.MAX_PAGES', 2):
            report = audit_lockfile(self.path, online=True, transport=pages)
        self.assertFalse(report['coverage']['complete'])
        self.assertIn('OSV_PAGE_LIMIT', {n['code'] for n in report['notices']})

    def test_failure_after_first_page_preserves_findings(self):
        calls = []
        def fake(payload):
            calls.append(payload)
            if len(calls) > 1: raise TimeoutError()
            return {'results': [{'vulns': [{'id': 'CVE-2026-12345'}], 'next_page_token': 'more'}]}
        report = audit_lockfile(self.path, online=True, transport=fake)
        self.assertFalse(report['coverage']['complete'])
        self.assertEqual(report['findings'][0]['advisory_id'], 'CVE-2026-12345')

    def test_advisory_ids_and_dates_are_not_trusted_urls(self):
        bads = ['../secret', 'https://evil', 'GHSA-x<script>', 'GHSA-x?secret', 'x' * 161]
        result = {'vulns': [{'id': x} for x in bads] + [{'id': 'GHSA-valid', 'modified': 'bad date'}, {'id': 'CVE-2026-12345', 'modified': '2026-11-17T10:00:00Z'}]}
        report = audit_lockfile(self.path, online=True, transport=lambda p: {'results': [result]})
        self.assertFalse(report['coverage']['complete'])
        self.assertEqual(len(report['findings']), 1)
        self.assertEqual(report['findings'][0]['source_url'], 'https://osv.dev/vulnerability/CVE-2026-12345')

    def test_batching_and_partial_results(self):
        self.write({f'node_modules/pkg{i}': package(f'pkg{i}') for i in range(3)})
        sent = []
        def fake(payload):
            sent.append(payload)
            return {'results': [{} for q in payload['queries']]}
        with patch('cyber.advisories.BATCH_SIZE', 2):
            report = audit_lockfile(self.path, online=True, transport=fake)
        self.assertEqual([len(p['queries']) for p in sent], [2, 1])
        self.assertEqual(report['coverage']['queried_packages'], 3)


class TransportTests(unittest.TestCase):
    def test_all_redirects_are_refused(self):
        self.assertIsNone(_NoRedirect().redirect_request(None, None, 302, 'moved', {}, 'https://evil.example'))

    def test_transport_uses_fixed_https_post_timeout_and_bound(self):
        seen = {}
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, size):
                seen['read_size'] = size
                return b'{"results": [{}]}'
        class Opener:
            def open(self, request, timeout):
                seen.update(url=request.full_url, method=request.method, timeout=timeout, data=json.loads(request.data))
                return Response()
        with patch('cyber.advisories.urllib.request.build_opener', return_value=Opener()):
            self.assertEqual(_transport({'queries': []}), {'results': [{}]})
        self.assertEqual(seen['url'], 'https://api.osv.dev/v1/querybatch')
        self.assertEqual(seen['method'], 'POST')
        self.assertLessEqual(seen['timeout'], 20)
        self.assertEqual(seen['read_size'], 4 * 1024 * 1024 + 1)

    def transport_with_bytes(self, raw):
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, size): return raw[:size]
        class Opener:
            def open(self, request, timeout): return Response()
        with patch('cyber.advisories.urllib.request.build_opener', return_value=Opener()):
            return _transport({'queries': []})

    def test_response_size_is_bounded(self):
        with patch('cyber.advisories.MAX_RESPONSE_BYTES', 16), self.assertRaises(ValueError):
            self.transport_with_bytes(b'x' * 17)

    def test_malformed_and_duplicate_key_responses_are_rejected(self):
        for raw in (b'\xff', b'not JSON', b'{"results": [], "results": []}'):
            with self.subTest(raw=raw[:30]), self.assertRaises(ValueError):
                self.transport_with_bytes(raw)
        # Recursion limits differ across Python releases; normalize the parser's
        # recursion error rather than depending on one interpreter's depth.
        with patch('cyber.advisories.json.loads', side_effect=RecursionError), self.assertRaises(ValueError):
            self.transport_with_bytes(b'[]')


if __name__ == '__main__':
    unittest.main()
