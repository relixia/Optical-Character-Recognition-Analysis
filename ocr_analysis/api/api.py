from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

#TODO: 
# rapor yazılacak //    tunneling   //      result page yapılacak    //     docstring yaz   //      test yazılacak

app = FastAPI()

templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="templates/static"), name="static")
