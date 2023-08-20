from fastapi import FastAPI, File, UploadFile, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import os
import pytesseract
from PIL import Image
from tasks.extractor import SensitiveInfoExtractor


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

    extractor = SensitiveInfoExtractor(extracted_text) #instance of the class
    sensitive_info = extractor.extract_sensitive_info()

    return templates.TemplateResponse(
        "result.html",
        {"uploaded_file_name": upload.filename, "extracted_text": extracted_text, "sensitive_info": sensitive_info, "request": request},
    )