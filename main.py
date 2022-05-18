from fastapi import FastAPI
import uvicorn


from endpoints.login import router as login_router
from endpoints.user import router as user_router

app = FastAPI()

app.include_router(user_router, tags=["user"])
app.include_router(login_router, tags=["login"])

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host='127.0.0.1',
        port=8080,
        reload=True,
        debug=True,
    )
