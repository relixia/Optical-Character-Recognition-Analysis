from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# TODO:
# response style değişecek
# ekstra: pytesseracct dışında diğer libleri de kullan ne kadar çok bilgi o kadar iyi

# COMPLETED:
# iban and its validation added


app = FastAPI()

templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="templates/static"), name="static")
