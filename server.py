from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict, EmailStr
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
import jwt
import bcrypt

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

app = FastAPI()
api_router = APIRouter(prefix="/api")
security = HTTPBearer()

JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key-change-in-production')
JWT_ALGORITHM = "HS256"

# Pydantic Models
class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    name: str
    email: str
    is_admin: bool = False
    wishlist: List[str] = []
    created_at: str

class Product(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    name: str
    description: str
    price: float
    images: List[str]
    sizes: List[str]
    colors: List[str]
    design_category: str
    stock: int
    rating: float = 0.0
    review_count: int = 0
    created_at: str

class ProductCreate(BaseModel):
    name: str
    description: str
    price: float
    images: List[str]
    sizes: List[str]
    colors: List[str]
    design_category: str
    stock: int

class Review(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    product_id: str
    user_id: str
    user_name: str
    rating: int
    comment: str
    created_at: str

class ReviewCreate(BaseModel):
    rating: int
    comment: str

class CartItem(BaseModel):
    product_id: str
    quantity: int
    size: str
    color: str

class Cart(BaseModel):
    model_config = ConfigDict(extra="ignore")
    user_id: str
    items: List[CartItem]
    updated_at: str

class OrderItem(BaseModel):
    product_id: str
    product_name: str
    quantity: int
    size: str
    color: str
    price: float

class Order(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    user_id: str
    user_name: str
    user_email: str
    items: List[OrderItem]
    total_amount: float
    shipping_address: dict
    status: str = "pending"
    created_at: str

class OrderCreate(BaseModel):
    items: List[OrderItem]
    total_amount: float
    shipping_address: dict

# Helper Functions
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_token(user_id: str) -> str:
    payload = {
        'user_id': user_id,
        'exp': datetime.now(timezone.utc) + timedelta(days=7)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    try:
        token = credentials.credentials
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get('user_id')
        user = await db.users.find_one({'id': user_id}, {'_id': 0, 'password': 0})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_admin_user(user: dict = Depends(get_current_user)) -> dict:
    if not user.get('is_admin'):
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

# Auth Routes
@api_router.post("/auth/register")
async def register(user_data: UserCreate):
    existing = await db.users.find_one({'email': user_data.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    user_id = str(uuid.uuid4())
    user_doc = {
        'id': user_id,
        'name': user_data.name,
        'email': user_data.email,
        'password': hash_password(user_data.password),
        'is_admin': False,
        'wishlist': [],
        'created_at': datetime.now(timezone.utc).isoformat()
    }
    
    await db.users.insert_one(user_doc)
    token = create_token(user_id)
    
    return {'token': token, 'user': {'id': user_id, 'name': user_data.name, 'email': user_data.email, 'is_admin': False}}

@api_router.post("/auth/login")
async def login(credentials: UserLogin):
    user = await db.users.find_one({'email': credentials.email})
    if not user or not verify_password(credentials.password, user['password']):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_token(user['id'])
    return {'token': token, 'user': {'id': user['id'], 'name': user['name'], 'email': user['email'], 'is_admin': user.get('is_admin', False)}}

@api_router.get("/auth/me", response_model=User)
async def get_me(user: dict = Depends(get_current_user)):
    return user

# Product Routes
@api_router.get("/products")
async def get_products(size: Optional[str] = None, color: Optional[str] = None, design: Optional[str] = None):
    query = {}
    if size:
        query['sizes'] = size
    if color:
        query['colors'] = color
    if design:
        query['design_category'] = design
    
    products = await db.products.find(query, {'_id': 0}).to_list(1000)
    return products

@api_router.get("/products/{product_id}")
async def get_product(product_id: str):
    product = await db.products.find_one({'id': product_id}, {'_id': 0})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    return product

@api_router.post("/products", response_model=Product)
async def create_product(product_data: ProductCreate, admin: dict = Depends(get_admin_user)):
    product_id = str(uuid.uuid4())
    product_doc = {
        'id': product_id,
        **product_data.model_dump(),
        'rating': 0.0,
        'review_count': 0,
        'created_at': datetime.now(timezone.utc).isoformat()
    }
    
    await db.products.insert_one(product_doc)
    return product_doc

@api_router.put("/products/{product_id}", response_model=Product)
async def update_product(product_id: str, product_data: ProductCreate, admin: dict = Depends(get_admin_user)):
    result = await db.products.find_one({'id': product_id}, {'_id': 0})
    if not result:
        raise HTTPException(status_code=404, detail="Product not found")
    
    update_data = product_data.model_dump()
    await db.products.update_one({'id': product_id}, {'$set': update_data})
    
    updated = await db.products.find_one({'id': product_id}, {'_id': 0})
    return updated

@api_router.delete("/products/{product_id}")
async def delete_product(product_id: str, admin: dict = Depends(get_admin_user)):
    result = await db.products.delete_one({'id': product_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Product not found")
    return {'message': 'Product deleted'}

# Review Routes
@api_router.get("/products/{product_id}/reviews")
async def get_reviews(product_id: str):
    reviews = await db.reviews.find({'product_id': product_id}, {'_id': 0}).to_list(1000)
    return reviews

@api_router.post("/products/{product_id}/reviews")
async def create_review(product_id: str, review_data: ReviewCreate, user: dict = Depends(get_current_user)):
    product = await db.products.find_one({'id': product_id})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    
    existing = await db.reviews.find_one({'product_id': product_id, 'user_id': user['id']})
    if existing:
        raise HTTPException(status_code=400, detail="You already reviewed this product")
    
    review_id = str(uuid.uuid4())
    review_doc = {
        'id': review_id,
        'product_id': product_id,
        'user_id': user['id'],
        'user_name': user['name'],
        **review_data.model_dump(),
        'created_at': datetime.now(timezone.utc).isoformat()
    }
    
    await db.reviews.insert_one(review_doc)
    
    reviews = await db.reviews.find({'product_id': product_id}).to_list(1000)
    avg_rating = sum(r['rating'] for r in reviews) / len(reviews)
    await db.products.update_one(
        {'id': product_id},
        {'$set': {'rating': round(avg_rating, 1), 'review_count': len(reviews)}}
    )
    
    return review_doc

# Cart Routes
@api_router.get("/cart")
async def get_cart(user: dict = Depends(get_current_user)):
    cart = await db.carts.find_one({'user_id': user['id']}, {'_id': 0})
    if not cart:
        return {'user_id': user['id'], 'items': [], 'updated_at': datetime.now(timezone.utc).isoformat()}
    return cart

@api_router.post("/cart")
async def add_to_cart(item: CartItem, user: dict = Depends(get_current_user)):
    cart = await db.carts.find_one({'user_id': user['id']})
    
    if not cart:
        cart_doc = {
            'user_id': user['id'],
            'items': [item.model_dump()],
            'updated_at': datetime.now(timezone.utc).isoformat()
        }
        await db.carts.insert_one(cart_doc)
    else:
        items = cart.get('items', [])
        found = False
        for i, existing_item in enumerate(items):
            if (existing_item['product_id'] == item.product_id and 
                existing_item['size'] == item.size and 
                existing_item['color'] == item.color):
                items[i]['quantity'] += item.quantity
                found = True
                break
        
        if not found:
            items.append(item.model_dump())
        
        await db.carts.update_one(
            {'user_id': user['id']},
            {'$set': {'items': items, 'updated_at': datetime.now(timezone.utc).isoformat()}}
        )
    
    return {'message': 'Item added to cart'}

@api_router.put("/cart/{product_id}")
async def update_cart_item(product_id: str, quantity: int, size: str, color: str, user: dict = Depends(get_current_user)):
    cart = await db.carts.find_one({'user_id': user['id']})
    if not cart:
        raise HTTPException(status_code=404, detail="Cart not found")
    
    items = cart.get('items', [])
    for item in items:
        if item['product_id'] == product_id and item['size'] == size and item['color'] == color:
            item['quantity'] = quantity
            break
    
    await db.carts.update_one(
        {'user_id': user['id']},
        {'$set': {'items': items, 'updated_at': datetime.now(timezone.utc).isoformat()}}
    )
    
    return {'message': 'Cart updated'}

@api_router.delete("/cart/{product_id}")
async def remove_from_cart(product_id: str, size: str, color: str, user: dict = Depends(get_current_user)):
    cart = await db.carts.find_one({'user_id': user['id']})
    if not cart:
        raise HTTPException(status_code=404, detail="Cart not found")
    
    items = [item for item in cart.get('items', []) 
             if not (item['product_id'] == product_id and item['size'] == size and item['color'] == color)]
    
    await db.carts.update_one(
        {'user_id': user['id']},
        {'$set': {'items': items, 'updated_at': datetime.now(timezone.utc).isoformat()}}
    )
    
    return {'message': 'Item removed from cart'}

# Wishlist Routes
@api_router.post("/wishlist/{product_id}")
async def add_to_wishlist(product_id: str, user: dict = Depends(get_current_user)):
    wishlist = user.get('wishlist', [])
    if product_id not in wishlist:
        wishlist.append(product_id)
        await db.users.update_one({'id': user['id']}, {'$set': {'wishlist': wishlist}})
    return {'message': 'Added to wishlist'}

@api_router.delete("/wishlist/{product_id}")
async def remove_from_wishlist(product_id: str, user: dict = Depends(get_current_user)):
    wishlist = user.get('wishlist', [])
    if product_id in wishlist:
        wishlist.remove(product_id)
        await db.users.update_one({'id': user['id']}, {'$set': {'wishlist': wishlist}})
    return {'message': 'Removed from wishlist'}

@api_router.get("/wishlist")
async def get_wishlist(user: dict = Depends(get_current_user)):
    wishlist_ids = user.get('wishlist', [])
    if not wishlist_ids:
        return []
    products = await db.products.find({'id': {'$in': wishlist_ids}}, {'_id': 0}).to_list(1000)
    return products

# Order Routes
@api_router.post("/orders")
async def create_order(order_data: OrderCreate, user: dict = Depends(get_current_user)):
    order_id = str(uuid.uuid4())
    order_doc = {
        'id': order_id,
        'user_id': user['id'],
        'user_name': user['name'],
        'user_email': user['email'],
        **order_data.model_dump(),
        'status': 'pending',
        'created_at': datetime.now(timezone.utc).isoformat()
    }
    
    await db.orders.insert_one(order_doc)
    await db.carts.delete_one({'user_id': user['id']})
    
    print(f"\n{'='*50}\nORDER CONFIRMATION EMAIL\n{'='*50}")
    print(f"To: {user['email']}")
    print(f"Subject: Order Confirmation - {order_id}")
    print(f"\nHi {user['name']},\n")
    print(f"Your order has been placed successfully!\n")
    print(f"Order ID: {order_id}")
    print(f"Total Amount: ${order_data.total_amount:.2f}\n")
    print(f"Items:")
    for item in order_data.items:
        print(f"  - {item.product_name} (Size: {item.size}, Color: {item.color}) x{item.quantity} - ${item.price:.2f}")
    print(f"\nShipping Address:")
    print(f"  {order_data.shipping_address.get('name')}")
    print(f"  {order_data.shipping_address.get('address')}")
    print(f"  {order_data.shipping_address.get('city')}, {order_data.shipping_address.get('state')} {order_data.shipping_address.get('zip')}")
    print(f"\nThank you for shopping with OVERSIZE_CULT!\n{'='*50}\n")
    
    return order_doc

@api_router.get("/orders")
async def get_user_orders(user: dict = Depends(get_current_user)):
    orders = await db.orders.find({'user_id': user['id']}, {'_id': 0}).sort('created_at', -1).to_list(1000)
    return orders

@api_router.get("/admin/orders")
async def get_all_orders(admin: dict = Depends(get_admin_user)):
    orders = await db.orders.find({}, {'_id': 0}).sort('created_at', -1).to_list(1000)
    return orders

app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
