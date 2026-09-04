"""Shared CLI for the three presentation modes."""
import argparse
from pathlib import Path
import sys

try:
    from .report_config import load_config
    from .report_input import load_input
    from .report_model import build_model
    from .report_layout import render_pdf
except ImportError:
    from report_config import load_config
    from report_input import load_input
    from report_model import build_model
    from report_layout import render_pdf


def main(argv=None, kind=None):
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8')
    parser = argparse.ArgumentParser(description='PDF из готовых показателей анализа 1.6 и срезов 1.8; без пересчёта.')
    parser.add_argument('--analysis-dir',type=Path,required=True)
    parser.add_argument('--slices-dir',type=Path)
    parser.add_argument('--report-config',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--overwrite',action='store_true')
    args = parser.parse_args(argv)
    try:
        config = load_config(args.report_config)
        if kind and config.settings['report_kind'] != kind:
            raise ValueError(f'This entry point requires report_kind={kind}')
        data = load_input(args.analysis_dir,args.slices_dir)
        model = build_model(data,config)
        render_pdf(model,config,data,args.output,args.overwrite)
    except Exception as exc:
        print(f'ERROR: {exc}',file=sys.stderr)
        return 2
    print(f'PDF: {args.output.resolve()}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
