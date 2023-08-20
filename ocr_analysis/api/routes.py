from fastapi import FastAPI, File, UploadFile, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import os
import pytesseract
from PIL import Image
from tasks.extractor import SensitiveInfoExtractor
from validation.validator import validate_urls, validate_domains, validate_credit_cards, validate_emails

#TODO: 
# email verifier yapılacak     06 AC 7250
# redis cache yapılacak
# rapor yazılacak
# result page yapılacak
# dynaconf eklenecek
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

    # Validate URLs
    validated_urls = validate_urls(sensitive_info.get("urls", []))
    sensitive_info["urls"] = validated_urls

    # Validate Domains
    validated_domains = validate_domains(sensitive_info.get("domains", []))
    sensitive_info["domains"] = validated_domains
    
    # Validate and Detect Credit Cards
    validated_credit_cards = validate_credit_cards(sensitive_info.get("credit_card_numbers", []))
    sensitive_info["credit_card_numbers"] = validated_credit_cards

    # Validate Emails
    validated_emails = validate_emails(sensitive_info.get("emails", []))
    sensitive_info["emails"] = validated_emails

    return JSONResponse(content={"content": extracted_text, "status": "successful", "findings": sensitive_info})
