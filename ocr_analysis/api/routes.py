from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse

from api.api import app, templates
from tasks.image_processor import process_image


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/result", response_class=HTMLResponse)
async def upload_file(request: Request, upload: UploadFile = File(...)):

    return process_image(upload)
