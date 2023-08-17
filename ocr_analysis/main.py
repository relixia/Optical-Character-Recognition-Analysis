from fastapi import FastAPI, File, UploadFile, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import os


app = FastAPI()

templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="templates/static"), name="static")

@app.get('/', response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post('/result', response_class=HTMLResponse)
async def upload_file(
    request: Request, upload: UploadFile = File(...)):
    print("Inside /result route")
    print("Uploaded filename:", upload.filename)

    return templates.TemplateResponse("result.html", {"uploaded_file_name": upload.filename, "request": request,})


if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=8000)
