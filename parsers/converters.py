import json
import xml.etree.ElementTree as ET
import csv
import openpyxl
import pdfplumber

def xml_to_json(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()
    def recurse(node):
        result = {"tag": node.tag, "attributes": node.attrib, "text": node.text.strip() if node.text else ""}
        children = [recurse(child) for child in node]
        if children:
            result["children"] = children
        return result
    return json.dumps(recurse(root), indent=2)

def csv_to_json(file_path):
    with open(file_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        return json.dumps([row for row in reader], indent=2)

def xls_to_json(file_path):
    wb = openpyxl.load_workbook(file_path, data_only=True)
    sheet = wb.active
    headers = [cell.value for cell in sheet[1]]
    data = []
    for row in sheet.iter_rows(min_row=2, values_only=True):
        data.append(dict(zip(headers, row)))
    return json.dumps(data, indent=2)

def pdf_to_json(file_path):
    data = []
    with pdfplumber.open(file_path) as pdf:
        for page in pdf.pages:
            text = page.extract_text()
            if text:
                data.append({"page": page.page_number, "text": text.strip()})
    return json.dumps(data, indent=2)