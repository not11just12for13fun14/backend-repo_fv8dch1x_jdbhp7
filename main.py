import os
import re
import base64
import secrets
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, EmailStr

from database import db, create_document, get_documents

app = FastAPI(title="PrintZest API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Utilities
phone_regex = re.compile(r"^\+?\d{10,14}$")


def validate_phone(phone: str) -> str:
    if not phone_regex.match(phone):
        raise HTTPException(status_code=400, detail="Invalid phone number format")
    return phone


# Models (request/response)
class OTPRequest(BaseModel):
    name: str
    phone: str

class OTPVerify(BaseModel):
    phone: str
    code: str

class AdminLogin(BaseModel):
    email: EmailStr
    password: str

class ProductIn(BaseModel):
    title: str
    description: Optional[str] = None
    price: float = Field(..., ge=0)
    image_url: Optional[str] = None
    in_stock: bool = True

class ProductOut(ProductIn):
    id: str

class OrderItemIn(BaseModel):
    product_id: str
    title: str
    price: float
    size: str
    quantity: int = Field(1, ge=1)

class OrderIn(BaseModel):
    items: List[OrderItemIn]
    payment_mode: str
    delivery_location: str

class SettingsIn(BaseModel):
    brand_name: Optional[str] = None
    logo_data_url: Optional[str] = None
    qr_data_url: Optional[str] = None
    welcome_message: Optional[str] = None


# Simple in-DB helpers
from bson.objectid import ObjectId

def to_str_id(doc):
    if doc is None:
        return None
    doc["id"] = str(doc.pop("_id"))
    return doc


def require_admin(authorization: Optional[str] = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing admin token")
    session = db["session"].find_one({"token": authorization})
    if not session:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = db["user"].find_one({"_id": ObjectId(session["user_id"])})
    if not user or user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    return str(user["_id"])  # admin user id


# Auth: Customer OTP flow
@app.post("/auth/request-otp")
def request_otp(payload: OTPRequest):
    phone = validate_phone(payload.phone)
    # Upsert customer
    user = db["user"].find_one({"phone": phone})
    if not user:
        create_document("user", {
            "name": payload.name,
            "phone": phone,
            "role": "customer",
            "is_active": True,
        })
    # Generate OTP (fixed 6 digits)
    code = f"{secrets.randbelow(1000000):06d}"
    expires = datetime.now(timezone.utc) + timedelta(minutes=5)
    db["otp"].delete_many({"phone": phone})
    create_document("otp", {"phone": phone, "code": code, "expires_at": expires})
    # For demo, return the code. In production, integrate SMS.
    return {"success": True, "message": "OTP sent", "demo_code": code}


@app.post("/auth/verify-otp")
def verify_otp(payload: OTPVerify):
    phone = validate_phone(payload.phone)
    otp = db["otp"].find_one({"phone": phone, "code": payload.code})
    if not otp or otp.get("expires_at") < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")
    user = db["user"].find_one({"phone": phone})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    token = secrets.token_urlsafe(24)
    create_document("session", {"user_id": str(user["_id"]), "token": token, "created_at": datetime.now(timezone.utc)})
    db["otp"].delete_many({"phone": phone})
    return {"success": True, "token": token, "user": {"id": str(user["_id"]), "name": user.get("name"), "phone": user["phone"], "role": user.get("role", "customer")}}


# Admin login (email/password). For demo, bootstrap default admin if none
@app.post("/admin/login")
def admin_login(payload: AdminLogin):
    admin = db["user"].find_one({"email": payload.email, "role": "admin"})
    if not admin:
        # bootstrap default admin with password 'admin123' if matches email
        if payload.password == "admin123":
            uid = create_document("user", {"name": "Admin", "email": payload.email, "phone": "+10000000000", "role": "admin", "is_active": True})
            admin = db["user"].find_one({"_id": ObjectId(uid)})
        else:
            raise HTTPException(status_code=401, detail="Invalid credentials")
    else:
        # naive password check placeholder (no stored hash in this scaffold)
        if payload.password != "admin123":
            raise HTTPException(status_code=401, detail="Invalid credentials")
    token = secrets.token_urlsafe(24)
    create_document("session", {"user_id": str(admin["_id"]), "token": token, "created_at": datetime.now(timezone.utc)})
    return {"success": True, "token": token}


# Users (admin)
@app.get("/users")
def list_users(admin_id: str = Depends(require_admin)):
    users = [to_str_id(u) for u in db["user"].find().sort("created_at", -1)]
    return users


# Products
@app.get("/products")
def list_products():
    items = [to_str_id(p) for p in db["product"].find().sort("created_at", -1)]
    return items

@app.post("/products")
def create_product(data: ProductIn, admin_id: str = Depends(require_admin)):
    pid = create_document("product", data.model_dump())
    prod = db["product"].find_one({"_id": ObjectId(pid)})
    return to_str_id(prod)

@app.delete("/products/{product_id}")
def delete_product(product_id: str, admin_id: str = Depends(require_admin)):
    db["product"].delete_one({"_id": ObjectId(product_id)})
    return {"success": True}


# Orders
@app.post("/orders")
def place_order(order: OrderIn, authorization: Optional[str] = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing session token")
    session = db["session"].find_one({"token": authorization})
    if not session:
        raise HTTPException(status_code=401, detail="Invalid session")
    user_id = session["user_id"]
    total = sum(item.price * item.quantity for item in order.items)
    oid = create_document("order", {
        "user_id": user_id,
        "items": [i.model_dump() for i in order.items],
        "payment_mode": order.payment_mode,
        "delivery_location": order.delivery_location,
        "status": "pending" if order.payment_mode == "COD" else "paid",
        "total_amount": total,
    })
    doc = db["order"].find_one({"_id": ObjectId(oid)})
    return to_str_id(doc)

@app.get("/orders/mine")
def my_orders(authorization: Optional[str] = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing session token")
    session = db["session"].find_one({"token": authorization})
    if not session:
        raise HTTPException(status_code=401, detail="Invalid session")
    orders = [to_str_id(o) for o in db["order"].find({"user_id": session["user_id"]}).sort("created_at", -1)]
    return orders

@app.get("/orders")
def all_orders(admin_id: str = Depends(require_admin)):
    orders = [to_str_id(o) for o in db["order"].find().sort("created_at", -1)]
    return orders

@app.patch("/orders/{order_id}")
def update_order_status(order_id: str, status: str, admin_id: str = Depends(require_admin)):
    db["order"].update_one({"_id": ObjectId(order_id)}, {"$set": {"status": status, "updated_at": datetime.now(timezone.utc)}})
    return {"success": True}


# Settings (logo + QR)
@app.get("/settings")
def get_settings():
    s = db["settings"].find_one() or {}
    if s and "_id" in s:
        s = to_str_id(s)
    if not s:
        # seed defaults
        sid = create_document("settings", {"brand_name": "PrintZest", "welcome_message": "Quality prints, fast delivery."})
        s = to_str_id(db["settings"].find_one({"_id": ObjectId(sid)}))
    return s

@app.post("/settings")
def set_settings(payload: SettingsIn, admin_id: str = Depends(require_admin)):
    s = db["settings"].find_one()
    data = {k: v for k, v in payload.model_dump().items() if v is not None}
    if s:
        db["settings"].update_one({"_id": s["_id"]}, {"$set": data})
        s = db["settings"].find_one({"_id": s["_id"]})
    else:
        sid = create_document("settings", data)
        s = db["settings"].find_one({"_id": ObjectId(sid)})
    return to_str_id(s)


@app.get("/")
def root():
    return {"service": "PrintZest API", "status": "ok"}

@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
    }
    try:
        response["db"] = "✅ Connected" if db is not None else "❌ Not Connected"
        response["collections"] = db.list_collection_names() if db else []
    except Exception as e:
        response["db"] = f"Error: {e}"
    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
