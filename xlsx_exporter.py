"""Pure-Python OpenXML (.xlsx) workbook generator with embedded images & ZIP bundle support."""

from __future__ import annotations

import io
import os
import re
import struct
import zipfile
from pathlib import Path
from xml.sax.saxutils import escape as xml_escape


def _col_letter(idx: int) -> str:
    """Convert 1-based column index to Excel column letter (1 -> A, 27 -> AA)."""
    out = []
    n = idx
    while n > 0:
        n, rem = divmod(n - 1, 26)
        out.append(chr(65 + rem))
    return "".join(reversed(out))


def _cell_ref(row_1: int, col_1: int) -> str:
    return f"{_col_letter(col_1)}{row_1}"


def _clean_xml_text(val) -> str:
    """Strip XML 1.0 illegal control characters cleanly."""
    s = str(val if val is not None else "")
    return re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F]", "", s)


def detect_image_size(raw: bytes, ext: str) -> tuple[int, int]:
    """Return (width_px, height_px) for PNG or JPEG without external libraries."""
    ext_l = ext.lower().lstrip(".")
    try:
        if ext_l == "png" and len(raw) >= 24 and raw[:8] == b"\x89PNG\r\n\x1a\n":
            w, h = struct.unpack(">II", raw[16:24])
            if w > 0 and h > 0:
                return w, h
        if ext_l in ("jpg", "jpeg") and len(raw) > 4 and raw[:2] == b"\xff\xd8":
            pos = 2
            while pos + 9 < len(raw):
                if raw[pos] != 0xFF:
                    pos += 1
                    continue
                marker = raw[pos + 1]
                pos += 2
                if marker in (0xD8, 0xD9, 0x01) or (0xD0 <= marker <= 0xD7):
                    continue
                if pos + 2 > len(raw):
                    break
                seg_len = struct.unpack(">H", raw[pos : pos + 2])[0]
                if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
                    if pos + 7 <= len(raw):
                        h, w = struct.unpack(">HH", raw[pos + 3 : pos + 7])
                        if w > 0 and h > 0:
                            return w, h
                    break
                if seg_len < 2:
                    break
                pos += seg_len
    except Exception:
        pass
    return 400, 300


def _fit_emu(w_px: int, h_px: int, max_w_px: int = 86, max_h_px: int = 62) -> tuple[int, int]:
    """Scale pixel dimensions proportionally within thumbnail box and convert to EMUs."""
    if w_px <= 0 or h_px <= 0:
        w_px, h_px = max_w_px, max_h_px
    scale = min(max_w_px / float(w_px), max_h_px / float(h_px), 1.0)
    # Also ensure tiny icons scale reasonably
    if max(w_px, h_px) < 40:
        scale = min(max_w_px / float(w_px), max_h_px / float(h_px))
    ew = max(1, round(w_px * scale * 9525))
    eh = max(1, round(h_px * scale * 9525))
    return ew, eh


def build_xlsx_bytes(sheets: list[dict]) -> bytes:
    """Build a valid multi-sheet OpenXML (.xlsx) byte stream with optional embedded images & hyperlinks.

    Each sheet dict:
      {
        "name": "Visitor Passes",
        "headers": ["ID", ...],
        "col_widths": [22, ...],
        "rows": [
           {
             "cells": ["VP-001", {"hyperlink": "url", "label": "Open"}, ...],
             "images": [{"col_1": 8, "bytes": b"...", "ext": "jpg"}, ...]  # 1-based column for thumbnail
           }, ...
        ]
      }
    """
    media_files: list[tuple[str, bytes]] = []  # ("xl/media/image1.jpg", raw)
    media_exts: set[str] = set()
    drawings: dict[int, list[dict]] = {}  # sheet_idx_1 -> list of drawing specs

    sheet_xml_parts: list[str] = []
    sheet_rels_parts: list[str] = []
    drawing_xml_parts: list[tuple[int, str, str]] = []  # (sheet_idx_1, drawing_xml, drawing_rels_xml)

    for s_idx, sheet in enumerate(sheets, start=1):
        headers = sheet.get("headers") or []
        col_widths = sheet.get("col_widths") or [18] * len(headers)
        rows = sheet.get("rows") or []

        cols_xml = "<cols>" + "".join(
            f'<col min="{i}" max="{i}" width="{w}" customWidth="1"/>'
            for i, w in enumerate(col_widths, start=1)
        ) + "</cols>"

        row_xml_list: list[str] = []
        # Header row (row 1)
        h_cells = "".join(
            f'<c r="{_cell_ref(1, c_idx)}" t="inlineStr" s="1"><is><t>{xml_escape(_clean_xml_text(h))}</t></is></c>'
            for c_idx, h in enumerate(headers, start=1)
        )
        row_xml_list.append(f'<row r="1" ht="26" customHeight="1">{h_cells}</row>')

        sheet_drawings: list[dict] = []
        for r_offset, row_obj in enumerate(rows, start=2):
            cells = row_obj.get("cells") or []
            imgs = row_obj.get("images") or []
            has_imgs = bool(imgs)
            row_ht = ' ht="56" customHeight="1"' if has_imgs else ' ht="22" customHeight="1"'
            c_xml: list[str] = []
            for c_idx, val in enumerate(cells, start=1):
                ref = _cell_ref(r_offset, c_idx)
                if isinstance(val, dict) and val.get("hyperlink"):
                    url = _clean_xml_text(val["hyperlink"]).replace('"', '""')
                    lbl_raw = _clean_xml_text(val.get("label") or val["hyperlink"])
                    lbl = lbl_raw.replace('"', '""')
                    formula = xml_escape(f'HYPERLINK("{url}","{lbl}")')
                    c_xml.append(f'<c r="{ref}" t="str" s="2"><f>{formula}</f><v>{xml_escape(lbl_raw)}</v></c>')
                else:
                    txt = xml_escape(_clean_xml_text(val))
                    c_xml.append(f'<c r="{ref}" t="inlineStr" s="0"><is><t>{txt}</t></is></c>')
            row_xml_list.append(f'<row r="{r_offset}"{row_ht}>{"".join(c_xml)}</row>')

            for img in imgs:
                raw = img.get("bytes") or b""
                ext = str(img.get("ext") or "jpg").lower().lstrip(".")
                if ext == "jpeg":
                    ext = "jpg"
                if ext not in ("jpg", "png") or not raw:
                    continue
                img_num = len(media_files) + 1
                media_name = f"image{img_num}.{ext}"
                media_files.append((f"xl/media/{media_name}", raw))
                media_exts.add(ext)
                w_px, h_px = detect_image_size(raw, ext)
                cx, cy = _fit_emu(w_px, h_px)
                sheet_drawings.append(
                    {
                        "col_0": max(0, int(img.get("col_1", 1)) - 1),
                        "row_0": r_offset - 1,
                        "cx": cx,
                        "cy": cy,
                        "media_name": media_name,
                        "pic_id": len(sheet_drawings) + 1,
                    }
                )

        drawing_ref_xml = ""
        if sheet_drawings:
            drawings[s_idx] = sheet_drawings
            drawing_ref_xml = '<drawing r:id="rId1"/>'
            sheet_rels_parts.append(
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                f'<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/drawing" Target="../drawings/drawing{s_idx}.xml"/>'
                "</Relationships>"
            )

            d_rels = [
                f'<Relationship Id="rId{idx}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="../media/{d["media_name"]}"/>'
                for idx, d in enumerate(sheet_drawings, start=1)
            ]
            anchors = []
            for idx, d in enumerate(sheet_drawings, start=1):
                anchors.append(
                    "<xdr:oneCellAnchor>"
                    f'<xdr:from><xdr:col>{d["col_0"]}</xdr:col><xdr:colOff>38100</xdr:colOff>'
                    f'<xdr:row>{d["row_0"]}</xdr:row><xdr:rowOff>38100</xdr:rowOff></xdr:from>'
                    f'<xdr:ext cx="{d["cx"]}" cy="{d["cy"]}"/>'
                    "<xdr:pic>"
                    f'<xdr:nvPicPr><xdr:cNvPr id="{d["pic_id"]}" name="Photo{d["pic_id"]}"/><xdr:cNvPicPr/></xdr:nvPicPr>'
                    f'<xdr:blipFill><a:blip r:embed="rId{idx}"/><a:stretch><a:fillRect/></a:stretch></xdr:blipFill>'
                    '<xdr:spPr><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></xdr:spPr>'
                    "</xdr:pic>"
                    "<xdr:clientData/>"
                    "</xdr:oneCellAnchor>"
                )
            d_xml = (
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<xdr:wsDr xmlns:xdr="http://schemas.openxmlformats.org/drawingml/2006/spreadsheetDrawing" '
                'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
                'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
                f'{"".join(anchors)}'
                "</xdr:wsDr>"
            )
            d_rels_xml = (
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                f'{"".join(d_rels)}'
                "</Relationships>"
            )
            drawing_xml_parts.append((s_idx, d_xml, d_rels_xml))
        else:
            sheet_rels_parts.append("")

        ws_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            '<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>'
            f"{cols_xml}"
            f'<sheetData>{"".join(row_xml_list)}</sheetData>'
            f"{drawing_ref_xml}"
            "</worksheet>"
        )
        sheet_xml_parts.append(ws_xml)

    # [Content_Types].xml
    ct_defaults = [
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>',
        '<Default Extension="xml" ContentType="application/xml"/>',
    ]
    if "jpg" in media_exts:
        ct_defaults.append('<Default Extension="jpg" ContentType="image/jpeg"/>')
    if "png" in media_exts:
        ct_defaults.append('<Default Extension="png" ContentType="image/png"/>')
    ct_overrides = [
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>',
        '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>',
    ]
    for s_idx in range(1, len(sheets) + 1):
        ct_overrides.append(
            f'<Override PartName="/xl/worksheets/sheet{s_idx}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        )
    for s_idx, _, _ in drawing_xml_parts:
        ct_overrides.append(
            f'<Override PartName="/xl/drawings/drawing{s_idx}.xml" ContentType="application/vnd.openxmlformats-officedocument.drawing+xml"/>'
        )
    content_types_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        f'{"".join(ct_defaults)}{"".join(ct_overrides)}'
        "</Types>"
    )

    root_rels_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
        "</Relationships>"
    )

    wb_sheets = []
    wb_rels = []
    for idx, sh in enumerate(sheets, start=1):
        safe_name = xml_escape(re.sub(r"[\[\]:*?/\\]", "-", str(sh.get("name") or f"Sheet{idx}"))[:31])
        wb_sheets.append(f'<sheet name="{safe_name}" sheetId="{idx}" r:id="rId{idx}"/>')
        wb_rels.append(
            f'<Relationship Id="rId{idx}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{idx}.xml"/>'
        )
    style_rid = len(sheets) + 1
    wb_rels.append(
        f'<Relationship Id="rId{style_rid}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
    )

    workbook_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        f'<sheets>{"".join(wb_sheets)}</sheets>'
        "</workbook>"
    )
    workbook_rels_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        f'{"".join(wb_rels)}'
        "</Relationships>"
    )

    styles_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<fonts count="3">'
        '<font><sz val="10"/><name val="Calibri"/></font>'
        '<font><b/><sz val="10"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font>'
        '<font><u/><sz val="10"/><color rgb="FF1D5FB8"/><name val="Calibri"/></font>'
        '</fonts>'
        '<fills count="3">'
        '<fill><patternFill patternType="none"/></fill>'
        '<fill><patternFill patternType="gray125"/></fill>'
        '<fill><patternFill patternType="solid"><fgColor rgb="FF157A54"/></patternFill></fill>'
        '</fills>'
        '<borders count="2">'
        '<border><left/><right/><top/><bottom/><diagonal/></border>'
        '<border><left style="thin"><color rgb="FFDDE6E0"/></left><right style="thin"><color rgb="FFDDE6E0"/></right><top style="thin"><color rgb="FFDDE6E0"/></top><bottom style="thin"><color rgb="FFDDE6E0"/></bottom></border>'
        '</borders>'
        '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
        '<cellXfs count="3">'
        '<xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyAlignment="1" applyBorder="1"><alignment vertical="center" wrapText="1"/></xf>'
        '<xf numFmtId="0" fontId="1" fillId="2" borderId="1" xfId="0" applyFont="1" applyFill="1" applyAlignment="1" applyBorder="1"><alignment vertical="center" horizontal="left" wrapText="1"/></xf>'
        '<xf numFmtId="0" fontId="2" fillId="0" borderId="1" xfId="0" applyFont="1" applyAlignment="1" applyBorder="1"><alignment vertical="center" wrapText="1"/></xf>'
        '</cellXfs>'
        "</styleSheet>"
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types_xml)
        zf.writestr("_rels/.rels", root_rels_xml)
        zf.writestr("xl/workbook.xml", workbook_xml)
        zf.writestr("xl/_rels/workbook.xml.rels", workbook_rels_xml)
        zf.writestr("xl/styles.xml", styles_xml)
        for s_idx, ws_xml in enumerate(sheet_xml_parts, start=1):
            zf.writestr(f"xl/worksheets/sheet{s_idx}.xml", ws_xml)
            if sheet_rels_parts[s_idx - 1]:
                zf.writestr(f"xl/worksheets/_rels/sheet{s_idx}.xml.rels", sheet_rels_parts[s_idx - 1])
        for s_idx, d_xml, d_rels_xml in drawing_xml_parts:
            zf.writestr(f"xl/drawings/drawing{s_idx}.xml", d_xml)
            zf.writestr(f"xl/drawings/_rels/drawing{s_idx}.xml.rels", d_rels_xml)
        for arc_path, raw in media_files:
            zf.writestr(arc_path, raw)
    return buf.getvalue()
