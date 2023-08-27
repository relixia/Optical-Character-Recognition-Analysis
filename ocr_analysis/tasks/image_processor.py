import imghdr, io, json, os
from tempfile import NamedTemporaryFile

import pytesseract, textract
from fastapi import HTTPException
from fastapi.responses import JSONResponse
from PIL import Image

from cache.cache_manager import cache_result, get_cached_result
from tasks.extractor import SensitiveInfoExtractor
from validation.validator import validate_fields


def simplify_findings(sensitive_info):
    simplified_info = []

    for field, values in sensitive_info.items():
        for value_info in values:
            if "validation" in value_info and value_info["validation"] == "valid":
                simplified_info.append(
                    {"value": value_info["value"], "type": value_info["type"]}
                )

    return simplified_info


class ImageProcessor:
    @staticmethod
    def process_image(upload):
        image_data = upload.file.read()

        image_format = imghdr.what(None, h=image_data)
        if not image_format:
            return JSONResponse(
                content={"error": "bad request. wrong file format"}, status_code=400
            )

        cached_result = get_cached_result(image_data)
        if cached_result:
            cached_result_dict = json.loads(cached_result)
            return JSONResponse(content=cached_result_dict)

        image = Image.open(io.BytesIO(image_data))
        extracted_text = ImageProcessor.extract_text(image)

        if not extracted_text.strip():
            raise HTTPException(status_code=204)

        extractor = SensitiveInfoExtractor(extracted_text)
        sensitive_info = extractor.extract_sensitive_info()

        validation_results = validate_fields(sensitive_info)
        simplified_findings = simplify_findings(validation_results)

        result_content = {
            "content": extracted_text,
            "status": "successful",
            "findings": simplified_findings,
        }

        cache_result(image_data, json.dumps(result_content))
        return JSONResponse(content=result_content)

    @staticmethod
    def extract_text(image):
        extracted_text_tesseract = pytesseract.image_to_string(image)  # pytesseract

        with NamedTemporaryFile(delete=False, suffix=".png") as temp_file:  # textractor
            image.save(temp_file, format="PNG")
        extracted_text_textract = textract.process(
            temp_file.name, encoding="utf-8", errors="replace"
        ).decode("utf-8")
        os.remove(temp_file.name)

        combined_extracted_text = extracted_text_tesseract + extracted_text_textract
        return combined_extracted_text
