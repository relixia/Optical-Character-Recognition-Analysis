import imghdr, io, json, os, cv2, imutils
from tempfile import NamedTemporaryFile
import numpy as np

import pytesseract, textract
from fastapi import HTTPException
from fastapi.responses import JSONResponse
from PIL import Image, ImageFilter

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
                content={"status": "bad request. wrong file format"}, status_code=400
            )

        cached_result = get_cached_result(image_data)
        if cached_result:
            cached_result_dict = json.loads(cached_result)
            return JSONResponse(content=cached_result_dict)

        image = Image.open(io.BytesIO(image_data))
        extracted_text = ImageProcessor.extract_text(image)
        extracted_text_tesseract = pytesseract.image_to_string(image)

        if not extracted_text.strip():
            extracted_text_tesseract = ImageProcessor.decrease_noise_second(image)

            if not (extracted_text_tesseract.strip() and len(extracted_text_tesseract.strip()) > 2):
                extracted_text_tesseract = ImageProcessor.decrease_noise_first(image)

                if not (extracted_text_tesseract.strip() and len(extracted_text_tesseract.strip()) > 2):
                    raise HTTPException(status_code=204)

        extractor = SensitiveInfoExtractor(extracted_text)
        sensitive_info = extractor.extract_sensitive_info()

        validation_results = validate_fields(sensitive_info)
        simplified_findings = simplify_findings(validation_results)

        result_content = {
            "content": extracted_text_tesseract,
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

    @staticmethod
    def decrease_noise_first(image):
        image = image.resize((850, 400))
        gray = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2GRAY)
        blur = cv2.GaussianBlur(gray, (5,5), 0)
        thresh = cv2.threshold(blur, 0, 255, cv2.THRESH_BINARY_INV + cv2.THRESH_OTSU)[1]

        kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (3,3))
        opening = cv2.morphologyEx(thresh, cv2.MORPH_OPEN, kernel, iterations=1)
        close = cv2.morphologyEx(opening, cv2.MORPH_CLOSE, kernel, iterations=3)

        invert = 255 - cv2.GaussianBlur(close, (3,3), 0)
        data = pytesseract.image_to_string(invert, lang='eng', config='--psm 6')

        return data

    @staticmethod
    def decrease_noise_second(image):
        th1 = 140
        th2 = 140
        sig = 1.5

        black_and_white = image.convert("L")
        first_threshold = black_and_white.point(lambda p: p > th1 and 255)
        blurred = first_threshold.filter(ImageFilter.GaussianBlur(radius=sig))
        final = blurred.point(lambda p: p > th2 and 255)
        final = final.filter(ImageFilter.EDGE_ENHANCE_MORE)
        final = final.filter(ImageFilter.SHARPEN)

        data = pytesseract.image_to_string(final, lang='eng', config='--psm 10 --oem 3 -c tessedit_char_whitelist=0123456789').strip()

        return data
