from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# TODO:
#   //     docstring yaz   //      test yazılacak
# date pattern
# response style değişecek
# validators diğerleri için de
# unique field kaydet sadece bi domain 3 kere görünmesin
# ekstra: pytesseract dışında diğer libleri de kullan ne kadar çok bilgi o kadar iyi


# COMPLETED:
# credit card pattern changed, 
# plate corrected
# hash takes by 3 types of hashes
# combolist corrected
# cached response corrected
# http204 handle
# http400 handle

app = FastAPI()

templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="templates/static"), name="static")
