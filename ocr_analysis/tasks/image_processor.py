import io, json
from PIL import Image
import pytesseract
from cache.cache_manager import cache_result, get_cached_result
from tasks.extractor import SensitiveInfoExtractor
from validation.validator import validate_fields


def process_image(upload):
    image_data = upload.file.read()

    cached_result = get_cached_result(image_data)
    if cached_result:
        return JSONResponse(content=cached_result)

    image = Image.open(io.BytesIO(image_data))
    extracted_text = pytesseract.image_to_string(image)

    if not extracted_text.strip():
        raise HTTPException(status_code=204)

    extractor = SensitiveInfoExtractor(extracted_text)
    sensitive_info = extractor.extract_sensitive_info()

    validation_results = validate_fields(sensitive_info)

    result_content = {
        "content": extracted_text,
        "status": "successful",
        "findings": sensitive_info,
    }

    cache_result(image_data, json.dumps(result_content))  # Convert to JSON string

    return JSONResponse(content=result_content)
