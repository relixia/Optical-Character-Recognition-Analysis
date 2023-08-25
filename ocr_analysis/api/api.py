from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# TODO:
# date pattern
# response style değişecek
# btc wallet ve validation eklenecek
# ekstra: pytesseracct dışında diğer libleri de kullan ne kadar çok bilgi o kadar iyi

# COMPLETED:
# unique field kaydet
# hash validation added
# tc id validation added
# plate validation added
# ip address validation added

app = FastAPI()

templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="templates/static"), name="static")
