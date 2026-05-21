from __future__ import annotations
import os
import urllib.parse
import zlib
from datetime import datetime
from typing import Any
import base64

import fitz
import structlog
import gostcrypto

from dotenv import load_dotenv
from fastapi import FastAPI, UploadFile, File, Form, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import traceback
import re
import time

# Настройка логирования
load_dotenv()
logger = structlog.get_logger()

app = FastAPI(title="CryptoSign Service")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Gost-Hash"],
)

# Глобальное хранилище сессий
PENDING_SESSIONS = {}

def calculate_gost_hash(data: bytes) -> str:
    hasher = gostcrypto.gosthash.new("streebog256")
    hasher.update(data)
    return hasher.hexdigest()

def draw_vector_stamp(cert_data: dict[str, str], page: fitz.Page, w: float, h: float):
    x0, y0 = 2, 2
    x1, y1 = w - 2, h - 2
    r = 10
    k = 0.552284749831
    
    def draw_full_rounded_rect(sh):
        sh.draw_line(fitz.Point(x0 + r, y0), fitz.Point(x1 - r, y0))
        sh.draw_bezier(fitz.Point(x1 - r, y0), fitz.Point(x1 - r + r*k, y0), fitz.Point(x1, y0 + r - r*k), fitz.Point(x1, y0 + r))
        sh.draw_line(fitz.Point(x1, y0 + r), fitz.Point(x1, y1 - r))
        sh.draw_bezier(fitz.Point(x1, y1 - r), fitz.Point(x1, y1 - r + r*k), fitz.Point(x1 - r + r*k, y1), fitz.Point(x1 - r, y1))
        sh.draw_line(fitz.Point(x1 - r, y1), fitz.Point(x0 + r, y1))
        sh.draw_bezier(fitz.Point(x0 + r, y1), fitz.Point(x0 + r - r*k, y1), fitz.Point(x0, y1 - r + r*k), fitz.Point(x0, y1 - r))
        sh.draw_line(fitz.Point(x0, y1 - r), fitz.Point(x0, y0 + r))
        sh.draw_bezier(fitz.Point(x0, y0 + r), fitz.Point(x0, y0 + r - r*k), fitz.Point(x0 + r - r*k, y0), fitz.Point(x0 + r, y0))

    # 1. Фон (светло-голубой)
    shape = page.new_shape()
    draw_full_rounded_rect(shape)
    shape.finish(fill=(0.96, 0.98, 1.0), color=None, fill_opacity=0.9)
    shape.commit()

    # 2. Синяя полоса сверху
    stripe_height = 22
    primary_color = (0.29, 0.239, 0.827)
    shape = page.new_shape()
    shape.draw_line(fitz.Point(x0, y0 + r), fitz.Point(x0, y0 + stripe_height))
    shape.draw_line(fitz.Point(x0, y0 + stripe_height), fitz.Point(x1, y0 + stripe_height))
    shape.draw_line(fitz.Point(x1, y0 + stripe_height), fitz.Point(x1, y0 + r))
    shape.draw_bezier(fitz.Point(x1, y0 + r), fitz.Point(x1, y0 + r - r*k), fitz.Point(x1 - r + r*k, y0), fitz.Point(x1 - r, y0))
    shape.draw_line(fitz.Point(x1 - r, y0), fitz.Point(x0 + r, y0))
    shape.draw_bezier(fitz.Point(x0 + r, y0), fitz.Point(x0 + r - r*k, y0), fitz.Point(x0, y0 + r - r*k), fitz.Point(x0, y0 + r))
    shape.finish(fill=primary_color, color=None, fill_opacity=1.0)
    shape.commit()

    # 3. Рамка
    shape = page.new_shape()
    draw_full_rounded_rect(shape)
    shape.finish(fill=None, color=primary_color, width=1.5, stroke_opacity=1.0)
    shape.commit()

    font_regular, font_bold = "fonts/DejaVuSans.ttf", "fonts/DejaVuSans-Bold.ttf"
    
    # Заголовок
    title_rect = fitz.Rect(x0 + 5, y0 + 4, x1 - 5, y0 + stripe_height)
    page.insert_textbox(
        title_rect, 
        "ДОКУМЕНТ ПОДПИСАН \nЭЛЕКТРОННОЙ ПОДПИСЬЮ", 
        fontsize=6, color=(1, 1, 1), fontname="dejavu-bold", fontfile=font_bold,
        align=fitz.TEXT_ALIGN_CENTER
    )
    
    font_obj = fitz.Font(fontfile=font_regular)
    fio = cert_data['fio']
    parts = fio.split()
    max_text_w = w - 16
    indent = "                   "
    fio_lines = []
    label_font_size = 5.5
    
    # 1. Если всё ФИО вмещается в одну строку — пишем сразу
    if font_obj.text_length(f"Владелец: {fio}", fontsize=label_font_size) <= max_text_w:
        fio_lines = [f"Владелец: {fio}"]
    else:
        # Безопасно достаем Фамилию, Имя и Отчество (даже если их нет)
        f = parts[0] if len(parts) > 0 else ""
        i = parts[1] if len(parts) > 1 else ""
        o = " ".join(parts[2:]) if len(parts) > 2 else ""

        # 2. Вмещается ФИ -> О отдельно
        if font_obj.text_length(f"Владелец: {f} {i}".strip(), fontsize=label_font_size) <= max_text_w:
            fio_lines = [f"Владелец: {f} {i}".strip()]
            if o: fio_lines.append(f"{indent}{o}")

        # 3. Вмещается Ф, и отдельно вмещается ИО -> пишем на 2 строчки
        elif font_obj.text_length(f"Владелец: {f}", fontsize=label_font_size) <= max_text_w and \
             font_obj.text_length(f"{indent}{i} {o}".strip(), fontsize=label_font_size) <= max_text_w:
            fio_lines = [f"Владелец: {f}", f"{indent}{i} {o}".strip()]

        # 4. В противном случае — Ф, И, О на каждой строчке отдельно
        else:
            fio_lines = [f"Владелец: {f}"]
            if i: fio_lines.append(f"{indent}{i}")
            if o: fio_lines.append(f"{indent}{o}")
            
    inn_val = cert_data.get('inn', 'Не указан')
    inn_label = "ИНН ЮЛ" if len(inn_val) == 10 else "ИНН"
    
    parts = cert_data['serial'].split()
    cert_line1 = f"Сертификат: {' '.join(parts[:6])}"
    cert_line2 = " ".join(parts[6:])

    labels = [
        cert_line1,
        cert_line2
    ] + fio_lines + [
        f"{inn_label}: {inn_val}",
        f"Действителен: с {cert_data['date_from']} по {cert_data['date_to']}",
        f"Дата подписания: {cert_data['current_date']}",
    ]
    
    line_height = 7.5
    max_line_w = max(font_obj.text_length(line.strip(), fontsize=label_font_size) for line in labels)

    # Вычисляем динамический отступ слева, чтобы центрировать весь блок
    tx = (w - max_line_w) / 2
    
    # 2. Центрирование по вертикали (остается вашей идеальной формулой)
    start_y = y0 + (stripe_height + h + label_font_size - (len(labels) - 1) * line_height) / 2
    
    # Отрисовка строк
    for i, line in enumerate(labels):
        page.insert_text(
            (tx, start_y + (i * line_height)), 
            line, 
            fontsize=label_font_size, 
            color=primary_color, 
            fontname="dejavu", 
            fontfile=font_regular
        )

def calculate_signature_rect(page, column_name):
    # Размеры штампа (ВОЗВРАЩАЕМ ИЗ СТАРОЙ ВЕРСИИ)
    stamp_width = 150
    stamp_height = 80
    margin = 40
    v_spacing = 5
    
    p_width = page.rect.width
    p_height = page.rect.height
    
    # 1. Определяем базовый X в зависимости от колонки
    if column_name == "left":
        x0 = margin
    elif column_name == "right":
        x0 = p_width - stamp_width - margin
    else: # center
        x0 = (p_width - stamp_width) / 2
        
    x1 = x0 + stamp_width
    
    # 2. Собираем координаты ВСЕХ существующих аннотаций и виджетов максимально надежно.
    # Мы используем три уровня проверки, чтобы точно увидеть даже кастомные подписи.
    existing_rects = []
    
    # Уровень 1: Стандартные аннотации
    for annot in page.annots():
        existing_rects.append(annot.rect)
        
    # Уровень 2: Виджеты форм (подписи часто живут здесь)
    for widget in page.widgets():
        existing_rects.append(widget.rect)
        
    # Уровень 3: Низкоуровневый разбор словаря страницы (на случай, если API PyMuPDF не успел проиндексировать новые объекты)
    try:
        doc = page.parent
        _, annots_val = doc.xref_get_key(page.xref, "Annots")
        if annots_val != "null":
            import re
            # Если это ссылка на массив объектов
            m = re.match(r"(\d+) 0 R", annots_val)
            raw_array = doc.xref_object(int(m.group(1))) if m else annots_val
            
            for ref in re.findall(r"(\d+) 0 R", raw_array):
                xref = int(ref)
                _, r_val = doc.xref_get_key(xref, "Rect")
                if r_val != "null":
                    coords = [float(x) for x in re.findall(r"[-+]?\d*\.\d+|\d+", r_val)]
                    if len(coords) == 4:
                        # Конвертируем из PDF координат (снизу-вверх) в координаты PyMuPDF (сверху-вниз)
                        r_topdown = fitz.Rect(coords[0], p_height - coords[3], coords[2], p_height - coords[1])
                        # Добавляем только если этот прямоугольник еще не в списке
                        if not any(r_topdown.intersect(er).area > 0.9 * r_topdown.area for er in existing_rects if hasattr(er, 'area')):
                            existing_rects.append(r_topdown)
    except:
        pass

    # 3. Ищем свободное место, начиная от нижнего поля и поднимаясь вверх
    curr_y1 = p_height - margin
    curr_y0 = curr_y1 - stamp_height
    
    while curr_y0 >= margin:
        proposed_rect = fitz.Rect(x0, curr_y0, x1, curr_y1)
        
        # Проверяем пересечение с любым найденным объектом
        overlap_found = False
        for r in existing_rects:
            # Если есть хотя бы минимальное пересечение — это место занято
            if proposed_rect.intersects(r):
                # Прыгаем выше этого объекта
                curr_y1 = r.y0 - v_spacing
                curr_y0 = curr_y1 - stamp_height
                overlap_found = True
                break
        
        if not overlap_found:
            # Свободное место найдено!
            return proposed_rect
            
    # 4. Если места на странице совсем нет — ставим в самый верх
    return fitz.Rect(x0, margin, x1, margin + stamp_height)

@app.post("/api/prepare-pdf")
async def prepare_pdf(
    file: UploadFile = File(...), serial: str = Form(...), fio: str = Form(...),
    inn: str = Form(...), date_from: str = Form(...), date_to: str = Form(...),
    current_date: str = Form(...), position: str = Form("center"),
    use_visual: bool = Form(True)
):
    try:
        file_bytes = await file.read()
        
        # Для инкрементального сохранения PyMuPDF нужен файл на диске
        input_temp = f"input_{os.urandom(8).hex()}.pdf"
        with open(input_temp, "wb") as f:
            f.write(file_bytes)
            
        # САМАЯ НАДЕЖНАЯ ПРОВЕРКА: Если в байтах есть /ByteRange, файл ПОДПИСАН.
        # В этом случае категорически нельзя делать garbage=4 или любую оптимизацию.
        has_signatures = b"/ByteRange" in file_bytes
            
        doc = fitz.open(input_temp)
        
        # Если подписей нет — оптимизируем файл перед первой подписью
        if not has_signatures:
            optimized_temp = f"opt_{os.urandom(8).hex()}.pdf"
            doc.save(optimized_temp, garbage=4, deflate=True, clean=True)
            doc.close()
            if os.path.exists(input_temp): os.remove(input_temp)
            input_temp = optimized_temp
            doc = fitz.open(input_temp)

        last_page = doc[len(doc)-1]
        last_page_xref = last_page.xref
        p_rect = last_page.rect
        
        cert_data = {"serial": serial, "fio": fio, "inn": inn, "date_from": date_from, "date_to": date_to, "current_date": current_date}
        
        w_xref = doc.get_new_xref()
        
        if use_visual:
            rect = calculate_signature_rect(last_page, position)
            w, h = rect.width, rect.height

            # 1. Рисуем векторную графику на изолированной ВРЕМЕННОЙ странице
            temp_doc = fitz.open()
            temp_page = temp_doc.new_page(width=w, height=h)
            
            draw_vector_stamp(cert_data, temp_page, w, h)
            
            # 2. Конвертируем временную графику во внутренний PDF-поток
            temp_pdf_bytes = temp_doc.tobytes()
            temp_pdf = fitz.open("pdf", temp_pdf_bytes)
            
            # Извлекаем ВСЕ потоки содержимого временной страницы (фон, полосы, текст)
            # Каждое действие shape.commit() и insert_text() создает новый поток в массиве /Contents
            contents_stream = b"\n".join(
                temp_pdf.xref_stream(xref) for xref in temp_pdf[0].get_contents()
            )
            
            # 3. Рекурсивно переносим все ресурсы (шрифты, графику) в структуру основного документа
            import re
            xref_map = {}
            
            def copy_pdf_object(src_xref):
                if src_xref in xref_map:
                    return xref_map[src_xref]
                
                dst_xref = doc.get_new_xref()
                xref_map[src_xref] = dst_xref
                
                obj_str = temp_pdf.xref_object(src_xref)
                
                def replace_ref(match):
                    old_ref = int(match.group(1))
                    if old_ref == 0: return match.group(0)
                    new_ref = copy_pdf_object(old_ref)
                    return f"{new_ref} {match.group(2)} R"
                    
                new_obj_str = re.sub(r'\b(\d+)\s+(\d+)\s+R\b', replace_ref, obj_str)
                doc.update_object(dst_xref, new_obj_str)
                
                if temp_pdf.xref_is_stream(src_xref):
                    doc.update_stream(dst_xref, temp_pdf.xref_stream(src_xref))
                    
                return dst_xref

            # Извлекаем словарь Resources и копируем все его зависимости (встроенные шрифты DejaVu)
            _, res_str = temp_pdf.xref_get_key(temp_pdf[0].xref, "Resources")
            
            def replace_ref_res(match):
                old_ref = int(match.group(1))
                if old_ref == 0: return match.group(0)
                new_ref = copy_pdf_object(old_ref)
                return f"{new_ref} {match.group(2)} R"
                
            new_res_str = re.sub(r'\b(\d+)\s+(\d+)\s+R\b', replace_ref_res, res_str)
            
            # 4. Объявляем его как Form XObject (изолированный векторный штамп)
            form_xref = doc.get_new_xref()
            form_dict = (
                f"<< /Type /XObject /Subtype /Form /BBox [0 0 {w:.2f} {h:.2f}] "
                f"/Resources {new_res_str} >>"
            )
            doc.update_object(form_xref, form_dict)
            doc.update_stream(form_xref, contents_stream)
            
            # 5. Формируем словарь внешнего вида /AP -> /N
            # Мы встраиваем ссылку прямо в w_dict!
            ap_str = f"/AP << /N {form_xref} 0 R >>"
            
            # Закрываем временные документы
            temp_pdf.close()
            temp_doc.close()
            
            # Координаты виджета для Adobe (в системе координат PDF)
            pdf_rect = f"[{rect.x0} {p_rect.y1 - rect.y1} {rect.x1} {p_rect.y1 - rect.y0}]"
            widget_already_in_annots = False
        else:
            widget_already_in_annots = False
            ap_str = ""
            pdf_rect = "[0 0 0 0]"
        
        sig_contents_size = 65536
        placeholder = "0" * (sig_contents_size * 2)
        field_name = f"Signature_{int(time.time())}"
        
        # 1. Создаем объект значения подписи (V)
        date_format = "%Y%m%d%H%M%S+03'00'"
        pdf_date = datetime.now().strftime(date_format)
        v_xref = doc.get_new_xref()
        v_dict = (
            f"<< /Type /Sig /Filter /CryptoPro#20PDF /SubFilter /adbe.pkcs7.detached "
            f"/ByteRange [0 1000000000 1000000000 1000000000] "
            f"/Contents <{placeholder}> "
            f"/M (D:{pdf_date}) >>"
        )
        doc.update_object(v_xref, v_dict)
        
        def append_to_pdf_array(obj_xref, key, new_ref):
            """Безопасно добавляет элемент в PDF-массив, обрабатывая прямые и косвенные ссылки."""
            _, val = doc.xref_get_key(obj_xref, key)
            if val == "null":
                doc.xref_set_key(obj_xref, key, f"[{new_ref}]")
            elif val.startswith("["):
                # Прямой массив: "[1 0 R 2 0 R]"
                new_arr = val.strip()[:-1] + f" {new_ref}]"
                doc.xref_set_key(obj_xref, key, new_arr)
            else:
                # Косвенная ссылка: "45 0 R"
                arr_xref = int(val.split()[0])
                arr_str = doc.xref_object(arr_xref).strip()
                if arr_str.startswith("["):
                    new_arr = arr_str[:-1] + f" {new_ref}]"
                    doc.update_object(arr_xref, new_arr)
        
        # 2. Обновляем (или создаем) словарь виджета
        # Теперь наш виджет содержит графику внутри /AP!
        w_dict = (
            f"<< /Type /Annot /Subtype /Widget /FT /Sig /T ({field_name}) "
            f"/Rect {pdf_rect} /V {v_xref} 0 R /F 4 /P {last_page_xref} 0 R {ap_str} >>"
        )
        doc.update_object(w_xref, w_dict)
        
        # 3. Регистрируем виджет в списке аннотаций страницы (только если его там еще нет)
        if not widget_already_in_annots:
            append_to_pdf_array(last_page_xref, "Annots", f"{w_xref} 0 R")
            
        # 4. РЕГИСТРАЦИЯ В ACROFORM
        catalog_xref = doc.pdf_catalog()
        _, acroform_val = doc.xref_get_key(catalog_xref, "AcroForm")
        
        if acroform_val == "null":
            af_xref = doc.get_new_xref()
            doc.update_object(af_xref, f"<< /Fields [{w_xref} 0 R] /SigFlags 3 /DA (/Helv 0 Tf 0 g ) >>")
            # Обновляем Catalog только если AcroForm не было
            doc.xref_set_key(catalog_xref, "AcroForm", f"{af_xref} 0 R")
        else:
            # Если AcroForm есть, работаем ТОЛЬКО с ним, не трогая Catalog
            af_xref = int(acroform_val.split()[0])
            append_to_pdf_array(af_xref, "Fields", f"{w_xref} 0 R")
            doc.xref_set_key(af_xref, "SigFlags", "3")

        # Для многократной подписи используем incremental=True
        doc.save(input_temp, incremental=True, encryption=fitz.PDF_ENCRYPT_KEEP) 
        doc.close()
        
        # 5. Динамический поиск и ByteRange (С КОНЦА ФАЙЛА - это намного быстрее)
        with open(input_temp, "rb") as f:
            content = bytearray(f.read())
        
        # Фикс бага PyMuPDF: меняем 65536 на 65535 в хвосте файла
        tail_start = max(0, len(content) - 50000)
        if b"0000000000 65536 f " in content[tail_start:]:
            new_tail = content[tail_start:].replace(b"0000000000 65536 f ", b"0000000000 65535 f ")
            content[tail_start:] = new_tail
            
        # Ищем именно НАШ плейсхолдер (длинная строка нулей) с КОНЦА файла
        placeholder_marker = b"/Contents"
        search_pos = len(content)
        contents_start = -1
        
        while True:
            search_pos = content.rfind(placeholder_marker, 0, search_pos)
            if search_pos == -1: break
            look_ahead = content[search_pos : search_pos + 100]
            if b"<00000000" in look_ahead:
                contents_start = search_pos
                break
            if search_pos == 0: break
            search_pos -= 1

        if contents_start == -1:
            raise ValueError("Signature placeholder /Contents <000... not found during reverse search")
            
        hex_start = content.find(b"<", contents_start) + 1
        hex_end = content.find(b">", hex_start)
        if hex_end == -1: raise ValueError("Closing > for Contents not found")
            
        br1, br2, br3, br4 = 0, hex_start - 1, hex_end + 1, len(content) - (hex_end + 1)
        real_br_str = f"/ByteRange [0 {br2:d} {br3:d} {br4:d}]".encode("ascii")
        
        # Ищем ByteRange плейсхолдер также с конца
        br_placeholder = b"/ByteRange [0 1000000000 1000000000 1000000000]"
        br_pos = content.rfind(br_placeholder)
        if br_pos == -1:
            br_regex = re.compile(rb"/ByteRange\s*\[\s*0\s+1000000000\s+1000000000\s+1000000000\s*\]")
            br_match = list(br_regex.finditer(content))[-1]
            br_pos = br_match.start()
            match_len = len(br_match.group(0))
        else:
            match_len = len(br_placeholder)
        
        real_br_str_padded = real_br_str.ljust(match_len, b" ")
        content[br_pos : br_pos + match_len] = real_br_str_padded
        
        hash_data = content[br1:br1+br2] + content[br3:br3+br4]
        calculated_hash = calculate_gost_hash(hash_data)
        
        session_id = os.urandom(16).hex()
        PENDING_SESSIONS[session_id] = {
            "content": bytes(content), 
            "hex_start": hex_start, 
            "hex_len": hex_end - hex_start,
            "filename": input_temp
        }
        
        return JSONResponse({"doc_id": session_id, "hash_to_sign": calculated_hash})
    except Exception as e:
        logger.error("Failed to prepare PDF", error=str(e))
        traceback.print_exc()
        return JSONResponse({"error": str(e)}, status_code=500)

@app.post("/api/hash-detached")
async def hash_detached(file: UploadFile) -> JSONResponse:
    try:
        file_bytes = await file.read()
        return JSONResponse({"hash": calculate_gost_hash(file_bytes)})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

@app.post("/api/stamp-only")
async def stamp_only(
    file: UploadFile, serial: str = Form(...), fio: str = Form(...), inn: str = Form(...),
    date_from: str = Form(...), date_to: str = Form(...), current_date: str = Form(...),
    position: str = Form("center")
) -> Response:
    try:
        file_bytes = await file.read()
        doc = fitz.open(stream=file_bytes, filetype="pdf")
        last_page = doc[len(doc)-1]
        rect = calculate_signature_rect(last_page, position)
        pix = render_stamp_pixmap({"serial": serial, "fio": fio, "inn": inn, "date_from": date_from, "date_to": date_to, "current_date": current_date}, rect)
        last_page.add_image_annot(rect, pixmap=pix)
        out_bytes = doc.write()
        doc.close()
        return Response(content=out_bytes, media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename*=UTF-8''{urllib.parse.quote(file.filename)}", "X-Gost-Hash": calculate_gost_hash(out_bytes)})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

@app.post("/api/assemble-pdf")
async def assemble_pdf(doc_id: str = Form(...), client_signature: str = Form(...)):
    """Вставляет готовую подпись в PDF. 
    При использовании CAdES-XLT1 (0x5d) все LTV данные уже внутри подписи.
    """
    try:
        if doc_id not in PENDING_SESSIONS: 
            return JSONResponse({"error": "Expired session"}, status_code=400)
            
        session = PENDING_SESSIONS.pop(doc_id)
        pdf_content = bytearray(session["content"])
        
        # Декодируем подпись (Base64 или Hex)
        try:
            sig_bytes = base64.b64decode(client_signature)
        except:
            sig_bytes = bytes.fromhex(client_signature)
            
        sig_hex = sig_bytes.hex().lower()
        hex_len = session["hex_len"]
        
        if len(sig_hex) > hex_len:
            return JSONResponse({"error": "Signature too large for placeholder"}, status_code=500)
            
        # Паддинг нулями до точной длины заглушки
        sig_hex_padded = sig_hex.ljust(hex_len, '0')
        start = session["hex_start"]
        pdf_content[start : start + hex_len] = sig_hex_padded.encode("ascii")
        
        # Удаляем временный файл
        if os.path.exists(session["filename"]): 
            os.remove(session["filename"])
            
        return Response(
            content=bytes(pdf_content), 
            media_type="application/pdf", 
            headers={"Content-Disposition": "attachment; filename=signed.pdf"}
        )
    except Exception as e:
        logger.error("Failed to assemble PDF", error=str(e))
        traceback.print_exc()
        return JSONResponse({"error": str(e)}, status_code=500)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)

