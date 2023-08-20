from fastapi import FastAPI, File, UploadFile, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import os
import pytesseract
from PIL import Image
from tasks.extractor import SensitiveInfoExtractor
from validation.validator import validate_fields

#TODO: 
# redis cache yapılacak
# rapor yazılacak
# result page yapılacak
# docstring yaz
# test yazılacak

app = FastAPI()

templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="templates/static"), name="static")

@app.get('/', response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post('/result', response_class=HTMLResponse)
async def upload_file(
    request: Request, upload: UploadFile = File(...)):

    image = Image.open(upload.file)
    extracted_text = pytesseract.image_to_string(image)

    if not extracted_text.strip():
        raise HTTPException(status_code=204)  #return HTTP 204 no content

    extractor = SensitiveInfoExtractor(extracted_text) #instance of the class
    sensitive_info = extractor.extract_sensitive_info()

    validation_results = validate_fields(sensitive_info)

    return JSONResponse(content={"content": extracted_text, "status": "successful", "findings": sensitive_info})
