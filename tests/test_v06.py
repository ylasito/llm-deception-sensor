"""High-fidelity protocol interoperability and evidence-digest regression tests."""
from __future__ import annotations
import json
import tempfile
from pathlib import Path
import unittest
from deceptionsensor.fidelity import plan, openai_response, ollama_response, fingerprint
from deceptionsensor.evidence import create_report, verify_report, write_private
from deceptionsensor.storage import JsonlSink
from test_sensor import running, request


class FidelityTests(unittest.TestCase):
    def test_required_tool_call_has_openai_shape(self):
        payload = {'messages': [{'role': 'user', 'content': 'SECRET_SHOULD_NOT_ECHO'}],
                   'tools': [{'type': 'function', 'function': {'name': 'lookup_demo', 'parameters': {'type': 'object'}}}],
                   'tool_choice': 'required'}
        r, chunks = openai_response(payload, 'chatcmpl-fixed', 'demo', 123)
        self.assertEqual(r['choices'][0]['finish_reason'], 'tool_calls')
        self.assertEqual(r['choices'][0]['message']['tool_calls'][0]['function']['name'], 'lookup_demo')
        self.assertEqual(chunks[-1]['choices'][0]['finish_reason'], 'tool_calls')
        self.assertNotIn('SECRET_SHOULD_NOT_ECHO', json.dumps(r) + json.dumps(chunks))
        self.assertEqual(fingerprint(payload)['tool_schema_count'], 1)

    def test_auto_and_bad_tool_schema_do_not_execute(self):
        payload = {'tools': [{'type': 'function', 'function': {'name': '../../etc/passwd'}}], 'tool_choice': 'required'}
        self.assertEqual(plan(payload)['kind'], 'text')
        self.assertEqual(plan({'tools':[{'function': {'name':'ok', 'parameters':{}}}]} )['kind'], 'text')

    def test_explicit_function_choice_and_bounded_tools(self):
        payload = {'tools':[{'type':'function','function':{'name':'fictional'}}],
                   'tool_choice': {'type':'function','function':{'name':'fictional'}}}
        self.assertEqual(plan(payload)['name'], 'fictional')
        self.assertEqual(plan({'tools':[{'type':'function','function':{'name':'n'+str(i)}} for i in range(30)],'tool_choice':'required'})['name'],'n0')

    def test_ollama_tool_call_shape(self):
        data = ollama_response({'tools':[{'function':{'name':'fictional'}}],'tool_choice':'required'}, 'model', '2026-01-01T00:00:00Z',True)
        self.assertEqual(data['message']['tool_calls'][0]['function']['arguments'], {})

    def test_streaming_and_json_tool_endpoints(self):
        with running() as (server, root):
            p = server.server_address[1]
            req = {'messages':[{'role':'user','content':'PRIVATE_CANARY_TEST'}], 'tools':[{'type':'function','function':{'name':'fictional'}}], 'tool_choice':'required'}
            code, _, body = request(p, 'POST', '/v1/chat/completions', req)
            self.assertEqual(code, 200)
            self.assertEqual(json.loads(body)['choices'][0]['finish_reason'],'tool_calls')
            code, _, body = request(p, 'POST', '/v1/chat/completions', {**req,'stream':True})
            self.assertEqual(code,200)
            self.assertIn('data: [DONE]',body)
            self.assertIn('tool_calls',body)
            code, _, body = request(p, 'POST', '/api/chat', {**req,'stream':False})
            self.assertEqual(code,200)
            self.assertEqual(json.loads(body)['message']['tool_calls'][0]['function']['name'],'fictional')
            self.assertNotIn('PRIVATE_CANARY_TEST', (root/'events.jsonl').read_text())
            self.assertIn('"requested_tool_execution":true', (root/'events.jsonl').read_text())


class EvidenceTests(unittest.TestCase):
    def _event(self, ts='2026-11-17T00:00:00Z', eid='a'*32):
        return {'event_kind':'request','capture_mode':'metadata','sensor_id':'local-sensor',
                'session_id':'b'*24,'ts':ts,'event_id':eid,'endpoint_family':'openai',
                'canary_hits':[{'id':'fake_system', 'kind':'system'}],
                'request_raw':'REAL_SECRET_WILL_NOT_EXPORT'}

    def test_evidence_redaction_digest_and_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            sink=JsonlSink(root,1000000,2)
            sink.emit(self._event())
            report=create_report(root,signing_key='x'*40)
            self.assertEqual(report['accepted_metadata_events'],1)
            self.assertNotIn('REAL_SECRET',json.dumps(report))
            self.assertTrue(verify_report(report,root,signing_key='x'*40))
            self.assertFalse(verify_report(report,root,signing_key='z'*40))
            path=root/'evidence.json'
            write_private(report,path)
            self.assertEqual(path.stat().st_mode & 0o777,0o600)
            with self.assertRaises(FileExistsError): write_private(report,path)
            sink.emit(self._event(eid='c'*32))
            self.assertFalse(verify_report(report,root,signing_key='x'*40))

    def test_deterministic_digest_reordering(self):
        with tempfile.TemporaryDirectory() as tmp:
            a=Path(tmp)/'a';b=Path(tmp)/'b'
            events=[self._event(eid='a'*32), self._event(eid='b'*32,ts='2026-11-17T00:00:01Z')]
            for e in events: JsonlSink(a,1000000,2).emit(e)
            for e in events[::-1]: JsonlSink(b,1000000,2).emit(e)
            self.assertEqual(create_report(a)['digest'],create_report(b)['digest'])

    def test_evidence_skips_raw_mode_and_invalid_sessions(self):
        with tempfile.TemporaryDirectory() as tmp:
            r=Path(tmp)
            s=JsonlSink(r,1000000,2)
            s.emit({**self._event(), 'capture_mode':'raw'})
            s.emit({**self._event(), 'session_id':'not-a-hash'})
            self.assertEqual(create_report(r)['accepted_metadata_events'],0)
            with self.assertRaises(ValueError): create_report(r,max_events=1)


if __name__ == '__main__': unittest.main()
