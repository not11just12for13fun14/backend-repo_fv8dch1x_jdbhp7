"""
Database Schemas for PrintZest

Each Pydantic model represents a MongoDB collection. The collection name is the
lowercased class name.
"""
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Literal
from datetime import datetime

class User(BaseModel):
    name: str = Field(..., description="Full name")
    phone: str = Field(..., description="E.164 phone number or local format validated in backend")
    email: Optional[EmailStr] = Field(None, description="Email (admins only)")
    role: Literal["customer", "admin"] = Field("customer")
    password_hash: Optional[str] = Field(None, description="SHA256 for admins")
    is_active: bool = Field(True)

class Product(BaseModel):
    title: str
    description: Optional[str] = None
    price: float = Field(..., ge=0)
    image_url: Optional[str] = None
    in_stock: bool = True

class OrderItem(BaseModel):
    product_id: str
    title: str
    price: float
    size: Literal["S","M","L"]
    quantity: int = Field(1, ge=1)

class Order(BaseModel):
    user_id: str
    items: List[OrderItem]
    payment_mode: Literal["Online", "COD"]
    delivery_location: str
    status: Literal["pending","paid","processing","shipped","delivered","cancelled"] = "pending"
    total_amount: float

class Settings(BaseModel):
    brand_name: str = "PrintZest"
    logo_data_url: Optional[str] = Field(None, description="Base64 data URL of logo")
    qr_data_url: Optional[str] = Field(None, description="Base64 data URL of payment QR")
    welcome_message: Optional[str] = "Quality prints, fast delivery."

class OTP(BaseModel):
    phone: str
    code: str
    expires_at: datetime

class Session(BaseModel):
    user_id: str
    token: str
    created_at: datetime
