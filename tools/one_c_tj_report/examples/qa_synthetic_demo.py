"""Render and structurally inspect every page of the synthetic PDF demos."""
from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import subprocess

from PIL import Image,ImageDraw
import pdfplumber


KINDS=('overview','comparison','history')
A4_LANDSCAPE=(841.8898,595.2756)
MM=72/25.4


def render(pdf,destination,pdftoppm):
    destination.mkdir(parents=True,exist_ok=True)
    for previous in destination.glob('page-*.png'):
        previous.unlink()
    prefix=destination/'page'
    subprocess.run([str(pdftoppm),'-png','-r','144','-cropbox',str(pdf),str(prefix)],check=True)
    return sorted(destination.glob('page-*.png'))


def inspect_pdf(pdf):
    issues=[]
    minimum=100.0
    appendix_page=None
    with pdfplumber.open(pdf) as document:
        total=len(document.pages)
        for number,page in enumerate(document.pages,1):
            if abs(page.width-A4_LANDSCAPE[0])>1 or abs(page.height-A4_LANDSCAPE[1])>1:
                issues.append(f'page {number}: not landscape A4 ({page.width} x {page.height})')
            text=page.extract_text() or ''
            if not text.strip():
                issues.append(f'page {number}: no extracted text')
            if f'Страница {number} из {total}' not in text:
                issues.append(f'page {number}: footer number absent')
            if 'ТЕХНИЧЕСКОЕ ПРИЛОЖЕНИЕ' in text:
                if appendix_page is not None:
                    issues.append(f'page {number}: duplicate appendix title')
                appendix_page=number
            expected_part='Техническое приложение |' if appendix_page is not None else 'Основной отчет |'
            if expected_part not in text:
                issues.append(f'page {number}: running part label absent')
            if '\ufffd' in text:
                issues.append(f'page {number}: replacement glyph in text')
            body=[]
            for char in page.chars:
                size=float(char.get('size') or 0)
                minimum=min(minimum,size)
                if char['top'] >= page.height-45:
                    continue
                body.append(char)
                if char['x0'] < 15*MM-1 or char['x1'] > page.width-15*MM+1:
                    issues.append(f'page {number}: text outside horizontal content frame')
                    break
                if char['top'] < 15*MM-1 or char['bottom'] > page.height-18*MM+1:
                    issues.append(f'page {number}: text outside vertical content frame')
                    break
            if not body:
                issues.append(f'page {number}: footer-only page')
        all_text='\n'.join((page.extract_text() or '') for page in document.pages)
    if appendix_page is None or appendix_page <= 2:
        issues.append('appendix does not start on a later dedicated page')
    for sentinel in ('ДЕМОНСТРАЦИОННЫЙ ОТЧЕТ','Частичные данные','нет наблюдений','показатель недоступен','V0001','СИНТЕТИЧЕСКИЙ SQL'):
        if sentinel not in all_text:
            issues.append(f'missing sentinel: {sentinel}')
    if minimum < 7.49:
        issues.append(f'minimum text size is {minimum:.2f} pt')
    return {'pages':total,'appendix_page':appendix_page,'minimum_font_pt':round(minimum,2),'issues':issues}


def contact_sheets(images,destination,kind):
    destination.mkdir(parents=True,exist_ok=True)
    for previous in destination.glob(f'{kind}-contact-*.png'):
        previous.unlink()
    per_sheet=12
    thumb_width=480
    label_height=22
    gutter=18
    outputs=[]
    with Image.open(images[0]) as sample:
        ratio=sample.height/sample.width
    thumb_height=round(thumb_width*ratio)
    for sheet_number,start in enumerate(range(0,len(images),per_sheet),1):
        batch=images[start:start+per_sheet]
        canvas=Image.new('RGB',(gutter+3*(thumb_width+gutter),gutter+4*(thumb_height+label_height+gutter)),'white')
        draw=ImageDraw.Draw(canvas)
        for offset,path in enumerate(batch):
            row,column=divmod(offset,3)
            x=gutter+column*(thumb_width+gutter)
            y=gutter+row*(thumb_height+label_height+gutter)
            with Image.open(path) as page:
                thumb=page.convert('RGB')
                thumb.thumbnail((thumb_width,thumb_height),Image.Resampling.LANCZOS)
                canvas.paste(thumb,(x,y+label_height))
            draw.text((x,y),f'{kind} page {start+offset+1:03d}',fill='black')
        output=destination/f'{kind}-contact-{sheet_number:02d}.png'
        canvas.save(output,optimize=True)
        outputs.append(output)
    return outputs


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--demo-dir',type=Path,default=Path('output/pdf/synthetic_demo'))
    parser.add_argument('--render-dir',type=Path,default=Path('tmp/pdfs/qa/final'))
    parser.add_argument('--pdftoppm',type=Path)
    parser.add_argument('--skip-render',action='store_true')
    args=parser.parse_args()
    executable=args.pdftoppm or shutil.which('pdftoppm')
    if not args.skip_render and not executable:
        raise SystemExit('pdftoppm not found; pass --pdftoppm')
    failed=False
    for kind in KINDS:
        pdf=args.demo_dir/f'synthetic_{kind}.pdf'
        result=inspect_pdf(pdf)
        image_dir=args.render_dir/kind
        images=sorted(image_dir.glob('page-*.png')) if args.skip_render else render(pdf,image_dir,executable)
        if len(images) != result['pages']:
            result['issues'].append(f'rendered {len(images)} images for {result["pages"]} pages')
        sheets=contact_sheets(images,args.render_dir/'contact-sheets',kind)
        print(f'{kind}: pages={result["pages"]}, appendix={result["appendix_page"]}, min_font={result["minimum_font_pt"]}, images={len(images)}, sheets={len(sheets)}')
        for issue in result['issues']:
            print('  ISSUE:',issue)
        failed=failed or bool(result['issues'])
    if failed:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
