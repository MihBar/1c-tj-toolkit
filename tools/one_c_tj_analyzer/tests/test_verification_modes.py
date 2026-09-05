"""Optional verification: real producer equivalence and deferred rejection."""
import contextlib
import io
import json
from pathlib import Path
import sys
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import analyze_1c_tj as analyzer
import derive_slices
from slice_input import load_bundle
from slice_config import SliceError
from source_identity import file_hash
from verify_analysis import verify as verify_analysis
from verify_slices import verify as verify_slices
from test_event_detail import call, db, record


class VerificationModesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.logs = self.root / 'logs'
        source = self.logs / 'capture/rphost_1/26090310.log'
        source.parent.mkdir(parents=True)
        source.write_text(call(CpuTime=0) + db(RowsAffected=0) +
                          record('EXCP', 2_000_000, Usr='User', OSThread='7', SessionID='A', Descr='Synthetic') +
                          call(30_000_000, 1_000_000, CpuTime='bad', Memory=-5), encoding='utf-8')
        self.config = Path(analyzer.__file__).parent / 'configs/stage1.full.example.json'

    def analyze(self, mode=None):
        output = self.root / (mode or 'default')
        args = [str(self.logs), '-o', str(output), '--capture-id', 'verification-test']
        if mode:
            args += ['--verification', mode]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(analyzer.run(args), 0)
        return output

    def slices(self, analysis, mode):
        output = self.root / ('slices-' + mode)
        result = derive_slices.run(['--analysis-dir', str(analysis), '--output-dir', str(output),
                                   '--config', str(self.config), '--verification', mode])
        return output, result

    def test_same_bundle_identity_and_all_slices_then_deferred_verification(self):
        with patch('slice_input.verify_detail', side_effect=AssertionError('deep verification invoked')):
            basic = self.analyze('basic')
            basic_slices, result = self.slices(basic, 'basic')
        self.assertEqual(result['status'], 'OK')
        a, b = load_bundle(basic, 'basic'), load_bundle(basic)
        self.assertEqual(a.bundle_id, b.bundle_id)
        self.assertEqual(a.input_files, b.input_files)
        self.assertEqual(a.calls, b.calls)
        full_slices, _ = self.slices(basic, 'full')
        for path in basic_slices.glob('*.csv'):
            self.assertEqual(path.read_bytes(), (full_slices / path.name).read_bytes(), path.name)
        before = {str(p): file_hash(p) for root in (basic, basic_slices) for p in root.iterdir()}
        self.assertEqual(verify_analysis(basic)[1], 0)
        self.assertEqual(verify_slices(basic, basic_slices)['status'], 'PASS')
        self.assertEqual(before, {str(p): file_hash(Path(p)) for p in before})

    def test_default_full_and_basic_produce_same_analytical_artifacts(self):
        full, basic = self.analyze(), self.analyze('basic')
        for path in full.iterdir():
            if path.name == 'analysis_metrics.json':
                a, b = (json.loads((root / path.name).read_text(encoding='utf-8')) for root in (full, basic))
                self.assertEqual(a.pop('verification')['mode'], 'full')
                self.assertEqual(b.pop('verification')['mode'], 'basic')
                self.assertEqual(a, b)
            else:
                self.assertEqual(path.read_bytes(), (basic / path.name).read_bytes(), path.name)

    def test_analytical_mismatch_is_deferred_but_structure_is_not(self):
        output = self.analyze('basic')
        manifest = output / 'analysis_metrics.json'
        value = json.loads(manifest.read_text(encoding='utf-8'))
        value['operations'][0]['p95_us'] += 1
        manifest.write_text(json.dumps(value), encoding='utf-8')
        load_bundle(output, 'basic')
        with self.assertRaises(SliceError):
            load_bundle(output)
        (output / 'call_observations.csv').write_text('bad\n', encoding='utf-8')
        for mode in ('full', 'basic'):
            with self.subTest(mode=mode), self.assertRaises(SliceError):
                load_bundle(output, mode)

    def test_hashes_remain_enforced(self):
        output = self.analyze('basic')
        with (output / 'analysis.sqlite').open('ab') as stream:
            stream.write(b'changed')
        with self.assertRaises(SliceError):
            load_bundle(output, 'basic')

    def test_invalid_mode_rejected_before_analysis(self):
        with patch.object(analyzer, 'discover_sources', side_effect=AssertionError('opened logs')):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                analyzer.run([str(self.logs), '--verification', 'off'])
            self.assertEqual(error.exception.code, 2)

    @unittest.skipUnless(os.name == 'nt', 'Windows BAT runner')
    def test_bat_both_modes_and_invalid_setting(self):
        runner = Path(__file__).resolve().parents[3] / 'scripts/run_analysis.bat'
        if not runner.exists():
            self.skipTest('standalone local deployment has its own runner')
        for mode in ('basic', 'full', 'off'):
            output = self.root / ('bat-' + mode)
            env = dict(os.environ, TJ_LOG_DIR=str(self.logs), TJ_SLICE_CONFIG=str(self.config),
                       TJ_OUTPUT_ROOT=str(output), TJ_PYTHON=sys.executable, TJ_VERIFICATION=mode)
            result = subprocess.run(['cmd.exe', '/d', '/c', str(runner)], env=env,
                                    capture_output=True, timeout=90)
            self.assertEqual(result.returncode, 10 if mode == 'off' else 0,
                             result.stdout.decode('utf-8', 'replace') + result.stderr.decode('utf-8', 'replace'))
            if mode == 'off':
                self.assertFalse(output.exists())
            else:
                self.assertEqual(b'Full slice verification' in result.stdout, mode == 'full')
                self.assertEqual(len(list(output.glob('run_*/slices/slice_manifest.json'))), 1)


if __name__ == '__main__':
    unittest.main()
