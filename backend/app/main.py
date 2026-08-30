from __future__ import annotations

from datetime import datetime, timedelta, timezone
from enum import Enum
import base64
import hashlib
import hmac
import json
import secrets
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, String, Integer, Float, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session, sessionmaker

DATABASE_URL = "sqlite:///./tokenlayer.db"
SECRET = "tokenlayer-demo-secret-change-in-production"
TOKEN_MINUTES = 120

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

class Base(DeclarativeBase):
    pass

class Role(str, Enum):
    ADMIN="admin"; PLATFORM_ADMIN="platform_admin"; COMPLIANCE="compliance"
    ISSUER="issuer"; INVESTOR="investor"; CUSTODIAN="custodian"; AUDITOR="auditor"

class User(Base):
    __tablename__="users"
    id: Mapped[int]=mapped_column(primary_key=True)
    name: Mapped[str]=mapped_column(String(120))
    email: Mapped[str]=mapped_column(String(180),unique=True,index=True)
    password_hash: Mapped[str]=mapped_column(String(255))
    role: Mapped[str]=mapped_column(String(40))
    organization_id: Mapped[Optional[int]]=mapped_column(ForeignKey("organizations.id"),nullable=True)
    active: Mapped[bool]=mapped_column(Boolean,default=True)
    mfa_enabled: Mapped[bool]=mapped_column(Boolean,default=False)
    kyc_status: Mapped[str]=mapped_column(String(30),default="pending")
    investor_class: Mapped[str]=mapped_column(String(50),default="retail")
    risk_profile: Mapped[str]=mapped_column(String(40),default="medium")
    created_at: Mapped[datetime]=mapped_column(DateTime,default=lambda:datetime.now(timezone.utc))

class Organization(Base):
    __tablename__="organizations"
    id: Mapped[int]=mapped_column(primary_key=True)
    name: Mapped[str]=mapped_column(String(180))
    legal_entity_name: Mapped[str]=mapped_column(String(180))
    registration_number: Mapped[str]=mapped_column(String(100))
    jurisdiction: Mapped[str]=mapped_column(String(80))
    organization_type: Mapped[str]=mapped_column(String(80))
    authorized_signatories: Mapped[str]=mapped_column(Text,default="")
    kyc_status: Mapped[str]=mapped_column(String(30),default="pending")
    compliance_status: Mapped[str]=mapped_column(String(30),default="pending")
    created_at: Mapped[datetime]=mapped_column(DateTime,default=lambda:datetime.now(timezone.utc))

class ManagedRole(Base):
    __tablename__="managed_roles"
    id: Mapped[int]=mapped_column(primary_key=True)
    name: Mapped[str]=mapped_column(String(80),unique=True)
    permissions: Mapped[str]=mapped_column(Text,default="")
    active: Mapped[bool]=mapped_column(Boolean,default=True)

class Asset(Base):
    __tablename__="assets"
    id: Mapped[int]=mapped_column(primary_key=True)
    organization_id: Mapped[int]=mapped_column(ForeignKey("organizations.id"))
    name: Mapped[str]=mapped_column(String(180)); symbol: Mapped[str]=mapped_column(String(30))
    category: Mapped[str]=mapped_column(String(80)); description: Mapped[str]=mapped_column(Text,default="")
    location: Mapped[str]=mapped_column(String(180),default=""); owner: Mapped[str]=mapped_column(String(180),default="")
    issuer_entity: Mapped[str]=mapped_column(String(180),default=""); jurisdiction: Mapped[str]=mapped_column(String(80))
    currency: Mapped[str]=mapped_column(String(10),default="USD"); total_value: Mapped[float]=mapped_column(Float)
    valuation_date: Mapped[str]=mapped_column(String(30),default=""); valuation_agency: Mapped[str]=mapped_column(String(180),default="")
    expected_yield: Mapped[float]=mapped_column(Float,default=0); maturity_date: Mapped[str]=mapped_column(String(30),default="")
    minimum_investment: Mapped[float]=mapped_column(Float,default=100); maximum_investment: Mapped[float]=mapped_column(Float,default=1000000)
    investment_currency: Mapped[str]=mapped_column(String(10),default="USD")
    legal_structure: Mapped[str]=mapped_column(String(80),default="SPV")
    custodian_name: Mapped[str]=mapped_column(String(180),default=""); custody_type: Mapped[str]=mapped_column(String(80),default="")
    custody_account: Mapped[str]=mapped_column(String(120),default=""); reserve_account: Mapped[str]=mapped_column(String(120),default="")
    escrow_account: Mapped[str]=mapped_column(String(120),default="")
    custody_verified: Mapped[bool]=mapped_column(Boolean,default=False)
    status: Mapped[str]=mapped_column(String(30),default="draft")
    created_at: Mapped[datetime]=mapped_column(DateTime,default=lambda:datetime.now(timezone.utc))

class AssetDocument(Base):
    __tablename__="asset_documents"
    id: Mapped[int]=mapped_column(primary_key=True)
    asset_id: Mapped[int]=mapped_column(ForeignKey("assets.id"))
    filename: Mapped[str]=mapped_column(String(255)); document_type: Mapped[str]=mapped_column(String(80))
    content_hash: Mapped[str]=mapped_column(String(128),default=""); created_at: Mapped[datetime]=mapped_column(DateTime,default=lambda:datetime.now(timezone.utc))

class TokenConfig(Base):
    __tablename__="token_configs"
    id: Mapped[int]=mapped_column(primary_key=True); asset_id: Mapped[int]=mapped_column(ForeignKey("assets.id"),unique=True)
    token_name: Mapped[str]=mapped_column(String(180)); token_symbol: Mapped[str]=mapped_column(String(30))
    token_type: Mapped[str]=mapped_column(String(80)); total_supply: Mapped[float]=mapped_column(Float); decimals: Mapped[int]=mapped_column(Integer,default=18)
    token_price: Mapped[float]=mapped_column(Float); minimum_purchase: Mapped[float]=mapped_column(Float); maximum_purchase: Mapped[float]=mapped_column(Float)
    transferable: Mapped[bool]=mapped_column(Boolean,default=True); fractionalization: Mapped[bool]=mapped_column(Boolean,default=True)
    lockup_period: Mapped[int]=mapped_column(Integer,default=0); investor_limit: Mapped[int]=mapped_column(Integer,default=1000)
    jurisdiction_restrictions: Mapped[str]=mapped_column(Text,default=""); whitelist_rules: Mapped[str]=mapped_column(Text,default="")
    blacklist_rules: Mapped[str]=mapped_column(Text,default=""); minted_supply: Mapped[float]=mapped_column(Float,default=0)

class ComplianceCheck(Base):
    __tablename__="compliance_checks"
    id: Mapped[int]=mapped_column(primary_key=True); asset_id: Mapped[int]=mapped_column(ForeignKey("assets.id"))
    check_type: Mapped[str]=mapped_column(String(80)); result: Mapped[str]=mapped_column(String(30))
    notes: Mapped[str]=mapped_column(Text,default=""); checked_by: Mapped[int]=mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime]=mapped_column(DateTime,default=lambda:datetime.now(timezone.utc))

class DID(Base):
    __tablename__="dids"
    id: Mapped[int]=mapped_column(primary_key=True); user_id: Mapped[int]=mapped_column(ForeignKey("users.id"),unique=True)
    did: Mapped[str]=mapped_column(String(180),unique=True); credential_type: Mapped[str]=mapped_column(String(80))
    credential_status: Mapped[str]=mapped_column(String(40),default="issued")

class SmartContract(Base):
    __tablename__="smart_contracts"
    id: Mapped[int]=mapped_column(primary_key=True); asset_id: Mapped[int]=mapped_column(ForeignKey("assets.id"))
    network: Mapped[str]=mapped_column(String(80)); template: Mapped[str]=mapped_column(String(100))
    address: Mapped[str]=mapped_column(String(120)); version: Mapped[str]=mapped_column(String(30),default="1.0.0")
    status: Mapped[str]=mapped_column(String(30),default="deployed"); tx_hash: Mapped[str]=mapped_column(String(120))
    paused: Mapped[bool]=mapped_column(Boolean,default=False); created_at: Mapped[datetime]=mapped_column(DateTime,default=lambda:datetime.now(timezone.utc))

class Wallet(Base):
    __tablename__="wallets"
    id: Mapped[int]=mapped_column(primary_key=True); user_id: Mapped[int]=mapped_column(ForeignKey("users.id"),unique=True)
    address: Mapped[str]=mapped_column(String(120),unique=True); wallet_type: Mapped[str]=mapped_column(String(50),default="custodial")
    whitelisted: Mapped[bool]=mapped_column(Boolean,default=False); frozen: Mapped[bool]=mapped_column(Boolean,default=False)
    created_at: Mapped[datetime]=mapped_column(DateTime,default=lambda:datetime.now(timezone.utc))

class Holding(Base):
    __tablename__="holdings"
    id: Mapped[int]=mapped_column(primary_key=True); wallet_id: Mapped[int]=mapped_column(ForeignKey("wallets.id"))
    asset_id: Mapped[int]=mapped_column(ForeignKey("assets.id")); quantity: Mapped[float]=mapped_column(Float,default=0)

class InvestmentOrder(Base):
    __tablename__="investment_orders"
    id: Mapped[int]=mapped_column(primary_key=True); investor_id: Mapped[int]=mapped_column(ForeignKey("users.id"))
    asset_id: Mapped[int]=mapped_column(ForeignKey("assets.id")); amount: Mapped[float]=mapped_column(Float)
    token_quantity: Mapped[float]=mapped_column(Float); status: Mapped[str]=mapped_column(String(40),default="pending")
    payment_id: Mapped[Optional[int]]=mapped_column(ForeignKey("payments.id"),nullable=True)
    settlement_id: Mapped[Optional[int]]=mapped_column(ForeignKey("settlements.id"),nullable=True)
    created_at: Mapped[datetime]=mapped_column(DateTime,default=lambda:datetime.now(timezone.utc))

class Payment(Base):
    __tablename__="payments"
    id: Mapped[int]=mapped_column(primary_key=True); order_id: Mapped[Optional[int]]=mapped_column(Integer,nullable=True)
    payer_id: Mapped[int]=mapped_column(ForeignKey("users.id")); amount: Mapped[float]=mapped_column(Float)
    method: Mapped[str]=mapped_column(String(60)); status: Mapped[str]=mapped_column(String(40),default="initiated")
    reference: Mapped[str]=mapped_column(String(100)); escrow_locked: Mapped[bool]=mapped_column(Boolean,default=False)
    created_at: Mapped[datetime]=mapped_column(DateTime,default=lambda:datetime.now(timezone.utc))

class Settlement(Base):
    __tablename__="settlements"
    id: Mapped[int]=mapped_column(primary_key=True); order_id: Mapped[Optional[int]]=mapped_column(Integer,nullable=True)
    buyer_id: Mapped[int]=mapped_column(ForeignKey("users.id")); seller_id: Mapped[Optional[int]]=mapped_column(ForeignKey("users.id"),nullable=True)
    asset_id: Mapped[int]=mapped_column(ForeignKey("assets.id")); quantity: Mapped[float]=mapped_column(Float)
    cash_amount: Mapped[float]=mapped_column(Float); status: Mapped[str]=mapped_column(String(40),default="pending")
    reconciliation_status: Mapped[str]=mapped_column(String(40),default="pending")
    exception_message: Mapped[str]=mapped_column(Text,default=""); created_at: Mapped[datetime]=mapped_column(DateTime,default=lambda:datetime.now(timezone.utc))

class TradeOrder(Base):
    __tablename__="trade_orders"
    id: Mapped[int]=mapped_column(primary_key=True); investor_id: Mapped[int]=mapped_column(ForeignKey("users.id"))
    asset_id: Mapped[int]=mapped_column(ForeignKey("assets.id")); side: Mapped[str]=mapped_column(String(10))
    quantity: Mapped[float]=mapped_column(Float); remaining_quantity: Mapped[float]=mapped_column(Float)
    price: Mapped[float]=mapped_column(Float); status: Mapped[str]=mapped_column(String(30),default="submitted")
    expires_at: Mapped[Optional[datetime]]=mapped_column(DateTime,nullable=True); created_at: Mapped[datetime]=mapped_column(DateTime,default=lambda:datetime.now(timezone.utc))

class Trade(Base):
    __tablename__="trades"
    id: Mapped[int]=mapped_column(primary_key=True); asset_id: Mapped[int]=mapped_column(ForeignKey("assets.id"))
    buy_order_id: Mapped[int]=mapped_column(ForeignKey("trade_orders.id")); sell_order_id: Mapped[int]=mapped_column(ForeignKey("trade_orders.id"))
    buyer_id: Mapped[int]=mapped_column(ForeignKey("users.id")); seller_id: Mapped[int]=mapped_column(ForeignKey("users.id"))
    quantity: Mapped[float]=mapped_column(Float); price: Mapped[float]=mapped_column(Float)
    settlement_status: Mapped[str]=mapped_column(String(30),default="pending")
    created_at: Mapped[datetime]=mapped_column(DateTime,default=lambda:datetime.now(timezone.utc))

class SessionToken(Base):
    __tablename__="session_tokens"
    id: Mapped[int]=mapped_column(primary_key=True); user_id: Mapped[int]=mapped_column(ForeignKey("users.id"))
    token_hash: Mapped[str]=mapped_column(String(128),unique=True); expires_at: Mapped[datetime]=mapped_column(DateTime)
    device: Mapped[str]=mapped_column(String(120),default="browser"); revoked: Mapped[bool]=mapped_column(Boolean,default=False)

class OTP(Base):
    __tablename__="otps"
    id: Mapped[int]=mapped_column(primary_key=True); user_id: Mapped[int]=mapped_column(ForeignKey("users.id"))
    code: Mapped[str]=mapped_column(String(10)); expires_at: Mapped[datetime]=mapped_column(DateTime); used: Mapped[bool]=mapped_column(Boolean,default=False)

class AuditLog(Base):
    __tablename__="audit_logs"
    id: Mapped[int]=mapped_column(primary_key=True); user_id: Mapped[Optional[int]]=mapped_column(ForeignKey("users.id"),nullable=True)
    organization_id: Mapped[Optional[int]]=mapped_column(ForeignKey("organizations.id"),nullable=True)
    action: Mapped[str]=mapped_column(String(120)); entity: Mapped[str]=mapped_column(String(80))
    entity_id: Mapped[str]=mapped_column(String(80),default=""); details: Mapped[str]=mapped_column(Text,default="")
    created_at: Mapped[datetime]=mapped_column(DateTime,default=lambda:datetime.now(timezone.utc))

Base.metadata.create_all(engine)

def db():
    s=SessionLocal()
    try: yield s
    finally: s.close()

def hash_password(password:str)->str:
    salt=secrets.token_bytes(16)
    digest=hashlib.scrypt(password.encode(),salt=salt,n=2**14,r=8,p=1)
    return base64.urlsafe_b64encode(salt+digest).decode()

def verify_password(password:str,stored:str)->bool:
    try:
        raw=base64.urlsafe_b64decode(stored.encode()); salt,digest=raw[:16],raw[16:]
        check=hashlib.scrypt(password.encode(),salt=salt,n=2**14,r=8,p=1)
        return hmac.compare_digest(digest,check)
    except Exception: return False

def issue_token(user:User,s:Session,device="browser"):
    raw=secrets.token_urlsafe(48)
    st=SessionToken(user_id=user.id,token_hash=hashlib.sha256(raw.encode()).hexdigest(),
                    expires_at=datetime.now(timezone.utc)+timedelta(minutes=TOKEN_MINUTES),device=device)
    s.add(st); s.commit()
    return raw

def current_user(authorization:Optional[str]=Header(None),s:Session=Depends(db)):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401,"Bearer token required")
    raw=authorization.split(" ",1)[1]
    st=s.query(SessionToken).filter(SessionToken.token_hash==hashlib.sha256(raw.encode()).hexdigest(),SessionToken.revoked==False).first()
    if not st or st.expires_at.replace(tzinfo=timezone.utc)<datetime.now(timezone.utc):
        raise HTTPException(401,"Invalid or expired session")
    u=s.get(User,st.user_id)
    if not u or not u.active: raise HTTPException(401,"Inactive user")
    return u

PERMS={
"admin":{"*"},
"platform_admin":{"dashboard:read","organizations:read","organizations:write","users:read","assets:read","assets:write","compliance:write","contracts:write","tokens:write","distribution:write","custody:write","audit:read","payments:read","settlement:read","settlement:write","trading:read","trading:write"},
"compliance":{"dashboard:read","assets:read","compliance:write","audit:read"},
"issuer":{"dashboard:read","assets:read","assets:write","tokens:write","contracts:write","distribution:write","audit:read","payments:read","settlement:read","settlement:write","trading:read","trading:write"},
"investor":{"marketplace:read","orders:write","wallet:write","portfolio:read","profile:write","payments:write","settlement:read","settlement:write","trading:read","trading:write"},
"custodian":{"dashboard:read","assets:read","custody:write","payments:read","settlement:read","settlement:write","audit:read","trading:read"},
"auditor":{"dashboard:read","audit:read","assets:read","organizations:read","trading:read","settlement:read"}
}

def require(permission:str):
    def check(u:User=Depends(current_user)):
        if "*" not in PERMS.get(u.role,set()) and permission not in PERMS.get(u.role,set()):
            raise HTTPException(403,f"Permission required: {permission}")
        return u
    return check

def audit(s,u,action,entity,eid="",details=""):
    s.add(AuditLog(user_id=u.id if u else None,organization_id=u.organization_id if u else None,
                   action=action,entity=entity,entity_id=str(eid),details=details)); s.commit()



def obj_dict(obj):
    return {c.name: getattr(obj, c.name) for c in obj.__table__.columns}

def obj_list(rows):
    return [obj_dict(x) for x in rows]

def accessible_asset(u,a):
    return u.role not in ("issuer","custodian") or u.organization_id==a.organization_id

class LoginIn(BaseModel): email:str; password:str; role:str; otp:Optional[str]=None; device:str="browser"
class RegisterIn(BaseModel): name:str; email:str; password:str=Field(min_length=8)
class OrgIn(BaseModel):
    name:str; legal_entity_name:str; registration_number:str; jurisdiction:str; organization_type:str; authorized_signatories:str=""
class AssetIn(BaseModel):
    name:str; symbol:str; category:str; description:str=""; location:str=""; owner:str=""; issuer_entity:str=""
    jurisdiction:str; currency:str="USD"; total_value:float=Field(gt=0); valuation_date:str=""; valuation_agency:str=""
    expected_yield:float=0; maturity_date:str=""; minimum_investment:float=100; maximum_investment:float=1000000
    investment_currency:str="USD"; legal_structure:str="SPV"; custodian_name:str=""; custody_type:str=""
    custody_account:str=""; reserve_account:str=""; escrow_account:str=""
class TokenIn(BaseModel):
    token_name:str; token_symbol:str; token_type:str; total_supply:float=Field(gt=0); decimals:int=18
    token_price:float=Field(gt=0); minimum_purchase:float=Field(gt=0); maximum_purchase:float=Field(gt=0)
    transferable:bool=True; fractionalization:bool=True; lockup_period:int=0; investor_limit:int=1000
    jurisdiction_restrictions:str=""; whitelist_rules:str=""; blacklist_rules:str=""
class OnboardIn(BaseModel):
    kyc_status:str="approved"; investor_class:str="accredited"; risk_profile:str="medium"
class DocumentIn(BaseModel): filename:str; document_type:str; content_base64:str=""
class InvestIn(BaseModel): asset_id:int; amount:float=Field(gt=0)
class PaymentIn(BaseModel): order_id:int; method:str
class TradeIn(BaseModel):
    asset_id:int; side:str; quantity:float=Field(gt=0); price:float=Field(gt=0); expires_minutes:int=1440
class CustodyIn(BaseModel): approved:bool=True
class MatchIn(BaseModel): asset_id:int

app=FastAPI(title="TokenLayer API — Phases 1–4",version="2.0.0")
app.add_middleware(CORSMiddleware,allow_origins=["http://localhost:5173","http://127.0.0.1:5173"],allow_credentials=True,allow_methods=["*"],allow_headers=["*"])

@app.on_event("startup")
def seed():
    s=SessionLocal()
    try:
        for rn,ps in PERMS.items():
            if not s.query(ManagedRole).filter(ManagedRole.name==rn).first():
                s.add(ManagedRole(name=rn,permissions=",".join(sorted(ps))))
        s.commit()
        org=s.query(Organization).first()
        if not org:
            org=Organization(name="Demo Issuer Organization",legal_entity_name="Demo Issuer Pvt Ltd",registration_number="TL-001",jurisdiction="India",organization_type="Issuer",authorized_signatories="Demo Signatory",kyc_status="approved",compliance_status="approved")
            s.add(org);s.commit();s.refresh(org)
        demos=[
            ("Super Admin","admin@tokenlayer.local","Admin@123","admin",None,"approved"),
            ("Platform Admin","platformadmin@tokenlayer.local","Platform@123","platform_admin",None,"approved"),
            ("Compliance Officer","compliance@tokenlayer.local","Compliance@123","compliance",None,"approved"),
            ("Issuer","issuer@tokenlayer.local","Issuer@123","issuer",org.id,"approved"),
            ("Custodian Bank","custodian@tokenlayer.local","Custodian@123","custodian",org.id,"approved"),
            ("Investor","investor@tokenlayer.local","Investor@123","investor",None,"approved"),
            ("Auditor","auditor@tokenlayer.local","Auditor@123","auditor",None,"approved"),
        ]
        for name,email,pw,role,oid,kyc in demos:
            if not s.query(User).filter(User.email==email).first():
                s.add(User(name=name,email=email,password_hash=hash_password(pw),role=role,organization_id=oid,kyc_status=kyc,investor_class="accredited" if role=="investor" else "n/a"))
        s.commit()
        if not s.query(Asset).first():
            a=Asset(organization_id=org.id,name="Bengaluru Commercial Property",symbol="BCP",category="Real Estate",description="Demo tokenizable commercial property.",location="Bengaluru",owner="Demo Issuer",issuer_entity="Demo Issuer Pvt Ltd",jurisdiction="India",currency="USD",total_value=1000000,valuation_date="2026-08-01",valuation_agency="Demo Valuation",expected_yield=8.5,maturity_date="2031-08-01",minimum_investment=1000,maximum_investment=250000,investment_currency="USD",legal_structure="SPV",custodian_name="Demo Custodian",custody_type="Custodian-held",custody_verified=True,status="live")
            s.add(a);s.commit();s.refresh(a)
            s.add(TokenConfig(asset_id=a.id,token_name="Bengaluru Property Token",token_symbol="BCP",token_type="Security Token",total_supply=100000,decimals=18,token_price=10,minimum_purchase=1000,maximum_purchase=250000,minted_supply=100000))
            s.add(SmartContract(asset_id=a.id,network="Mock EVM",template="SecurityToken",address="0x"+secrets.token_hex(20),tx_hash="0x"+secrets.token_hex(32)))
            s.commit()
        inv=s.query(User).filter(User.email=="investor@tokenlayer.local").first()
        if inv and not s.query(Wallet).filter(Wallet.user_id==inv.id).first():
            s.add(Wallet(user_id=inv.id,address="0x"+secrets.token_hex(20),wallet_type="custodial",whitelisted=True));s.commit()
    finally:
        s.close()

@app.get("/")
def root(): return {"service":"TokenLayer","implemented_phases":[1,2,3,4],"next_phases":[5,6,7],"docs":"/docs"}

@app.post("/auth/register")
def register(x:RegisterIn,s:Session=Depends(db)):
    if s.query(User).filter(User.email==x.email.lower()).first(): raise HTTPException(400,"Email already registered")
    u=User(name=x.name,email=x.email.lower(),password_hash=hash_password(x.password),role="investor")
    s.add(u); s.commit(); s.refresh(u); audit(s,u,"REGISTER","User",u.id,"Investor registration")
    return {"id":u.id,"message":"Registered"}

@app.post("/auth/request-otp")
def request_otp(email:str,s:Session=Depends(db)):
    u=s.query(User).filter(User.email==email.lower()).first()
    if not u: raise HTTPException(404,"User not found")
    code=f"{secrets.randbelow(1000000):06d}"
    s.add(OTP(user_id=u.id,code=code,expires_at=datetime.now(timezone.utc)+timedelta(minutes=5))); s.commit()
    return {"message":"Demo OTP generated","otp":code,"expires_in_seconds":300}

@app.post("/auth/login")
def login(x:LoginIn,s:Session=Depends(db)):
    u=s.query(User).filter(User.email==x.email.lower()).first()
    if not u or not verify_password(x.password,u.password_hash): raise HTTPException(401,"Invalid credentials")
    if x.role not in PERMS or u.role != x.role:
        raise HTTPException(403,"Selected portal role does not match this account")
    if u.mfa_enabled:
        if not x.otp: raise HTTPException(401,"OTP required")
        otp=s.query(OTP).filter(OTP.user_id==u.id,OTP.code==x.otp,OTP.used==False).order_by(OTP.id.desc()).first()
        if not otp or otp.expires_at.replace(tzinfo=timezone.utc)<datetime.now(timezone.utc): raise HTTPException(401,"Invalid OTP")
        otp.used=True; s.commit()
    t=issue_token(u,s,x.device); audit(s,u,"LOGIN","User",u.id,"Successful login")
    return {"access_token":t,"token_type":"bearer","user":{"id":u.id,"name":u.name,"email":u.email,"role":u.role,"organization_id":u.organization_id,"kyc_status":u.kyc_status}}

@app.post("/auth/logout")
def logout(u=Depends(current_user),authorization:Optional[str]=Header(None),s:Session=Depends(db)):
    raw=authorization.split(" ",1)[1]; st=s.query(SessionToken).filter(SessionToken.token_hash==hashlib.sha256(raw.encode()).hexdigest()).first()
    if st: st.revoked=True; s.commit()
    audit(s,u,"LOGOUT","User",u.id,"Session revoked"); return {"message":"Logged out"}

@app.post("/auth/forgot-password")
def forgot_password(email:str,s:Session=Depends(db)):
    u=s.query(User).filter(User.email==email.lower()).first()
    if not u: return {"message":"If the account exists, a reset token was generated"}
    token=secrets.token_urlsafe(24); audit(s,u,"PASSWORD_RESET_REQUEST","User",u.id,"Demo reset token generated")
    return {"message":"Demo reset token generated","reset_token":token}

@app.post("/auth/reset-password")
def reset_password(email:str,new_password:str,reset_token:str,s:Session=Depends(db)):
    if len(new_password)<8: raise HTTPException(400,"Password must be at least 8 characters")
    if not reset_token: raise HTTPException(400,"Reset token required")
    u=s.query(User).filter(User.email==email.lower()).first()
    if not u: raise HTTPException(404,"User not found")
    u.password_hash=hash_password(new_password); s.commit(); audit(s,u,"PASSWORD_RESET","User",u.id,"Password changed")
    return {"message":"Password reset completed"}

@app.get("/me")
def me(u=Depends(current_user)): return {"id":u.id,"name":u.name,"email":u.email,"role":u.role,"organization_id":u.organization_id,"kyc_status":u.kyc_status}

@app.get("/sessions")
def sessions(u=Depends(current_user),s:Session=Depends(db)):
    return s.query(SessionToken).filter(SessionToken.user_id==u.id).all()

@app.get("/roles")
def roles(u=Depends(require("users:read")),s:Session=Depends(db)): return obj_list(s.query(ManagedRole).order_by(ManagedRole.id).all())

@app.post("/roles")
def create_role(name:str,permissions:str="",u=Depends(require("users:read")),s:Session=Depends(db)):
    if s.query(ManagedRole).filter(ManagedRole.name==name).first(): raise HTTPException(400,"Role already exists")
    r=ManagedRole(name=name,permissions=permissions,active=True); s.add(r); s.commit(); s.refresh(r); audit(s,u,"CREATE","Role",r.id,name); return obj_dict(r)

@app.patch("/roles/{role_id}")
def update_role(role_id:int,name:Optional[str]=None,permissions:Optional[str]=None,active:Optional[bool]=None,u=Depends(require("users:read")),s:Session=Depends(db)):
    r=s.get(ManagedRole,role_id)
    if not r: raise HTTPException(404,"Role not found")
    if name is not None:r.name=name
    if permissions is not None:r.permissions=permissions
    if active is not None:r.active=active
    s.commit(); audit(s,u,"UPDATE","Role",r.id,r.name); return obj_dict(r)

@app.delete("/roles/{role_id}")
def delete_role(role_id:int,u=Depends(require("users:read")),s:Session=Depends(db)):
    r=s.get(ManagedRole,role_id)
    if not r: raise HTTPException(404,"Role not found")
    r.active=False; s.commit(); audit(s,u,"SUSPEND","Role",r.id,r.name); return obj_dict(r)

@app.get("/organizations")
def orgs(u=Depends(require("organizations:read")),s:Session=Depends(db)): return obj_list(s.query(Organization).order_by(Organization.id.desc()).all())

@app.post("/organizations")
def create_org(x:OrgIn,u=Depends(require("organizations:write")),s:Session=Depends(db)):
    o=Organization(**x.model_dump()); s.add(o); s.commit(); s.refresh(o); audit(s,u,"CREATE","Organization",o.id,o.name); return obj_dict(o)

@app.get("/users")
def users(u=Depends(require("users:read")),s:Session=Depends(db)): return obj_list(s.query(User).order_by(User.id.desc()).all())

@app.get("/assets")
def assets(u=Depends(current_user),s:Session=Depends(db)):
    q=s.query(Asset)
    if u.role in ("issuer","custodian"): q=q.filter(Asset.organization_id==u.organization_id)
    return obj_list(q.order_by(Asset.id.desc()).all())

@app.post("/assets")
def create_asset(x:AssetIn,u=Depends(require("assets:write")),s:Session=Depends(db)):
    oid=u.organization_id
    if not oid:
        first=s.query(Organization).first()
        if not first: raise HTTPException(400,"Organization required")
        oid=first.id
    a=Asset(**x.model_dump(),organization_id=oid,status="draft"); s.add(a); s.commit(); s.refresh(a)
    audit(s,u,"CREATE","Asset",a.id,a.name); return obj_dict(a)

@app.post("/assets/{asset_id}/documents")
def add_document(asset_id:int,x:DocumentIn,u=Depends(require("assets:write")),s:Session=Depends(db)):
    a=s.get(Asset,asset_id)
    if not a or not accessible_asset(u,a): raise HTTPException(404,"Asset not found")
    digest=hashlib.sha256(x.content_base64.encode()).hexdigest() if x.content_base64 else ""
    d=AssetDocument(asset_id=asset_id,filename=x.filename,document_type=x.document_type,content_hash=digest)
    s.add(d); s.commit(); s.refresh(d); audit(s,u,"UPLOAD","AssetDocument",d.id,x.filename); return obj_dict(d)

@app.get("/assets/{asset_id}/documents")
def docs(asset_id:int,u=Depends(current_user),s:Session=Depends(db)): return obj_list(s.query(AssetDocument).filter(AssetDocument.asset_id==asset_id).all())

@app.post("/assets/{asset_id}/submit")
def submit(asset_id:int,u=Depends(require("assets:write")),s:Session=Depends(db)):
    a=s.get(Asset,asset_id)
    if not a or not accessible_asset(u,a): raise HTTPException(404,"Asset not found")
    a.status="submitted"; s.commit(); audit(s,u,"SUBMIT","Asset",asset_id,"Submitted for review"); return obj_dict(a)

@app.get("/compliance/pending")
def pending(u=Depends(require("compliance:write")),s:Session=Depends(db)): return obj_list(s.query(Asset).filter(Asset.status.in_(["submitted","under_review"])).all())

@app.post("/assets/{asset_id}/compliance/approve")
def approve(asset_id:int,u=Depends(require("compliance:write")),s:Session=Depends(db)):
    a=s.get(Asset,asset_id)
    if not a: raise HTTPException(404,"Asset not found")
    for typ in ["KYC/KYB","AML/Sanctions","PEP","Jurisdiction","Investor Eligibility","Investment Limits","Asset Documentation"]:
        s.add(ComplianceCheck(asset_id=asset_id,check_type=typ,result="passed",notes="Demo rules engine",checked_by=u.id))
    a.status="approved"; s.commit(); audit(s,u,"APPROVE","Asset",asset_id,"Compliance approved"); return obj_dict(a)

@app.post("/assets/{asset_id}/custody")
def custody(asset_id:int,x:CustodyIn,u=Depends(require("custody:write")),s:Session=Depends(db)):
    a=s.get(Asset,asset_id)
    if not a: raise HTTPException(404,"Asset not found")
    a.custody_verified=x.approved
    if x.approved and a.status=="approved": a.status="approved"
    s.commit(); audit(s,u,"CUSTODY_VERIFY","Asset",asset_id,str(x.approved)); return obj_dict(a)

@app.post("/tokens/{asset_id}/configure")
def configure_token(asset_id:int,x:TokenIn,u=Depends(require("tokens:write")),s:Session=Depends(db)):
    a=s.get(Asset,asset_id)
    if not a or a.status!="approved" or not a.custody_verified: raise HTTPException(400,"Asset must be compliance approved and custody verified")
    tc=s.query(TokenConfig).filter(TokenConfig.asset_id==asset_id).first()
    if tc:
        for k,v in x.model_dump().items(): setattr(tc,k,v)
    else: tc=TokenConfig(asset_id=asset_id,**x.model_dump()); s.add(tc)
    s.commit(); s.refresh(tc); audit(s,u,"CONFIGURE","TokenConfig",tc.id,tc.token_symbol); return obj_dict(tc)

@app.get("/tokens/{asset_id}")
def token(asset_id:int,u=Depends(current_user),s:Session=Depends(db)):
    tc=s.query(TokenConfig).filter(TokenConfig.asset_id==asset_id).first()
    if not tc: raise HTTPException(404,"Token not configured")
    return obj_dict(tc)

@app.post("/contracts/{asset_id}/deploy")
def deploy(asset_id:int,u=Depends(require("contracts:write")),s:Session=Depends(db)):
    tc=s.query(TokenConfig).filter(TokenConfig.asset_id==asset_id).first()
    a=s.get(Asset,asset_id)
    if not tc or not a: raise HTTPException(400,"Token configuration required")
    sc=SmartContract(asset_id=asset_id,network="Mock EVM",template=tc.token_type,address="0x"+secrets.token_hex(20),tx_hash="0x"+secrets.token_hex(32))
    s.add(sc); a.status="tokenized"; s.commit(); s.refresh(sc); audit(s,u,"DEPLOY","SmartContract",sc.id,sc.address); return obj_dict(sc)

@app.get("/contracts")
def contracts(u=Depends(current_user),s:Session=Depends(db)): return obj_list(s.query(SmartContract).all())

@app.post("/contracts/{contract_id}/pause")
def pause(contract_id:int,u=Depends(require("contracts:write")),s:Session=Depends(db)):
    sc=s.get(SmartContract,contract_id)
    if not sc: raise HTTPException(404,"Contract not found")
    sc.paused=True; s.commit(); audit(s,u,"PAUSE","SmartContract",contract_id,"Paused"); return obj_dict(sc)

@app.post("/contracts/{contract_id}/resume")
def resume(contract_id:int,u=Depends(require("contracts:write")),s:Session=Depends(db)):
    sc=s.get(SmartContract,contract_id)
    if not sc: raise HTTPException(404,"Contract not found")
    sc.paused=False; s.commit(); audit(s,u,"RESUME","SmartContract",contract_id,"Resumed"); return obj_dict(sc)

@app.post("/contracts/{contract_id}/upgrade")
def upgrade_contract(contract_id:int,u=Depends(require("contracts:write")),s:Session=Depends(db)):
    sc=s.get(SmartContract,contract_id)
    if not sc: raise HTTPException(404,"Contract not found")
    major,minor,patch=[int(x) for x in sc.version.split(".")]
    sc.version=f"{major}.{minor+1}.0"
    sc.tx_hash="0x"+secrets.token_hex(32)
    s.commit();audit(s,u,"UPGRADE","SmartContract",sc.id,sc.version);return obj_dict(sc)

@app.get("/contracts/{contract_id}/events")
def contract_events(contract_id:int,u=Depends(current_user),s:Session=Depends(db)):
    sc=s.get(SmartContract,contract_id)
    if not sc: raise HTTPException(404,"Contract not found")
    logs=s.query(AuditLog).filter(AuditLog.entity=="SmartContract",AuditLog.entity_id==str(contract_id)).order_by(AuditLog.id.desc()).limit(25).all()
    return [{"event":x.action,"details":x.details,"created_at":x.created_at} for x in logs]

@app.post("/tokens/{asset_id}/mint")
def mint(asset_id:int,quantity:float=Query(gt=0),u=Depends(require("tokens:write")),s:Session=Depends(db)):
    tc=s.query(TokenConfig).filter(TokenConfig.asset_id==asset_id).first()
    sc=s.query(SmartContract).filter(SmartContract.asset_id==asset_id).first()
    if not tc or not sc: raise HTTPException(400,"Token and contract required")
    if tc.minted_supply+quantity>tc.total_supply: raise HTTPException(400,"Supply exceeded")
    tc.minted_supply+=quantity; a=s.get(Asset,asset_id); a.status="live"; s.commit(); audit(s,u,"MINT","TokenConfig",tc.id,f"{quantity} tokens"); return {"quantity":quantity,"tx_hash":"0x"+secrets.token_hex(32),"minted_supply":tc.minted_supply}

@app.get("/dashboard/summary")
def dashboard_summary(u=Depends(current_user),s:Session=Depends(db)):
    if u.role == "investor":
        raise HTTPException(403,"Use investor dashboard")
    q=s.query(Asset)
    if u.role in ("issuer","custodian") and u.organization_id:
        q=q.filter(Asset.organization_id==u.organization_id)
    arr=q.all()
    token_total=0
    for a in arr:
        tc=s.query(TokenConfig).filter(TokenConfig.asset_id==a.id).first()
        token_total += tc.minted_supply if tc else 0
    return {
        "total_assets":len(arr),
        "total_asset_value":sum(a.total_value for a in arr),
        "assets_draft":sum(a.status=="draft" for a in arr),
        "assets_under_review":sum(a.status in ("submitted","under_review") for a in arr),
        "live_assets":sum(a.status=="live" for a in arr),
        "total_tokens_issued":token_total,
        "total_investors":s.query(User).filter(User.role=="investor").count(),
        "funds_raised":sum(o.amount for o in s.query(InvestmentOrder).all()),
        "pending_settlements":s.query(Settlement).filter(Settlement.status!="completed").count(),
        "audit_events":s.query(AuditLog).count(),
    }

@app.get("/compliance/checks")
def compliance_checks(u=Depends(current_user),s:Session=Depends(db)):
    if u.role not in ("admin","platform_admin","compliance","issuer","custodian","auditor"):
        raise HTTPException(403,"Compliance access required")
    q=s.query(ComplianceCheck).order_by(ComplianceCheck.id.desc())
    return obj_list(q.limit(100).all())

@app.get("/identity")
def identity(u=Depends(current_user),s:Session=Depends(db)):
    did=s.query(DID).filter(DID.user_id==u.id).first()
    if not did:
        did=DID(user_id=u.id,did="did:tokenlayer:"+secrets.token_hex(16),credential_type="KYC Verified" if u.kyc_status=="approved" else "Pending Verification",credential_status="issued" if u.kyc_status=="approved" else "pending")
        s.add(did);s.commit();s.refresh(did)
    return {"user":obj_dict(u),"did":obj_dict(did),"credentials":[{"type":did.credential_type,"status":did.credential_status},{"type":"AML Screened","status":"passed" if u.kyc_status=="approved" else "pending"}]}

@app.post("/tokens/{asset_id}/distribute")
def distribute(asset_id:int,investor_id:int,quantity:float=Query(gt=0),u=Depends(require("distribution:write")),s:Session=Depends(db)):
    tc=s.query(TokenConfig).filter(TokenConfig.asset_id==asset_id).first()
    if not tc or tc.minted_supply < quantity: raise HTTPException(400,"Insufficient minted supply")
    inv=s.get(User,investor_id)
    if not inv or inv.role!="investor": raise HTTPException(404,"Investor not found")
    w=s.query(Wallet).filter(Wallet.user_id==inv.id).first()
    if not w: w=Wallet(user_id=inv.id,address="0x"+secrets.token_hex(20),wallet_type="custodial",whitelisted=inv.kyc_status=="approved");s.add(w);s.commit();s.refresh(w)
    h=s.query(Holding).filter(Holding.wallet_id==w.id,Holding.asset_id==asset_id).first()
    if h:h.quantity+=quantity
    else:s.add(Holding(wallet_id=w.id,asset_id=asset_id,quantity=quantity))
    s.commit();audit(s,u,"DISTRIBUTE","Holding",asset_id,f"Investor {investor_id}; {quantity} tokens");return {"asset_id":asset_id,"investor_id":investor_id,"quantity":quantity,"wallet":w.address,"status":"allocated"}

@app.get("/dashboard/issuer")
def issuer_dashboard(u=Depends(require("dashboard:read")),s:Session=Depends(db)):
    q=s.query(Asset)
    if u.organization_id:q=q.filter(Asset.organization_id==u.organization_id)
    arr=q.all(); return {"total_assets":len(arr),"total_asset_value":sum(a.total_value for a in arr),
        "assets_draft":sum(a.status=="draft" for a in arr),"assets_under_review":sum(a.status in ("submitted","under_review") for a in arr),
        "live_assets":sum(a.status=="live" for a in arr),"total_tokens_issued":sum((s.query(TokenConfig).filter(TokenConfig.asset_id==a.id).first().minted_supply if s.query(TokenConfig).filter(TokenConfig.asset_id==a.id).first() else 0) for a in arr),
        "total_investors":s.query(User).filter(User.role=="investor").count(),"funds_raised":sum(o.amount for o in s.query(InvestmentOrder).all())}

@app.post("/investor/onboarding")
def onboarding(x:OnboardIn,u=Depends(require("profile:write")),s:Session=Depends(db)):
    if u.role!="investor": raise HTTPException(403,"Investor account required")
    u.kyc_status=x.kyc_status; u.investor_class=x.investor_class; u.risk_profile=x.risk_profile
    did=s.query(DID).filter(DID.user_id==u.id).first()
    if not did: did=DID(user_id=u.id,did="did:tokenlayer:"+secrets.token_hex(16),credential_type="KYC Verified",credential_status="issued"); s.add(did)
    w=s.query(Wallet).filter(Wallet.user_id==u.id).first()
    if not w: w=Wallet(user_id=u.id,address="0x"+secrets.token_hex(20),whitelisted=x.kyc_status=="approved"); s.add(w)
    else: w.whitelisted=x.kyc_status=="approved"
    s.commit(); audit(s,u,"ONBOARD","Investor",u.id,x.model_dump_json()); return {"kyc_status":u.kyc_status,"investor_class":u.investor_class,"risk_profile":u.risk_profile,"did":did.did,"wallet":w.address}

@app.get("/investor/dashboard")
def investor_dashboard(u=Depends(require("portfolio:read")),s:Session=Depends(db)):
    if u.role!="investor": raise HTTPException(403,"Investor account required")
    w=s.query(Wallet).filter(Wallet.user_id==u.id).first(); hs=s.query(Holding).filter(Holding.wallet_id==w.id).all() if w else []
    orders=s.query(InvestmentOrder).filter(InvestmentOrder.investor_id==u.id).all()
    current=0
    for h in hs:
        tc=s.query(TokenConfig).filter(TokenConfig.asset_id==h.asset_id).first(); current+=h.quantity*(tc.token_price if tc else 0)
    return {"kyc_status":u.kyc_status,"investor_class":u.investor_class,"risk_profile":u.risk_profile,
            "total_investment":sum(o.amount for o in orders if o.status=="completed"),"current_value":current,"holdings":obj_list(hs),"orders":obj_list(orders)}

@app.get("/marketplace")
def marketplace(search:str="",category:str="",risk:str="",min_yield:Optional[float]=None,max_yield:Optional[float]=None,
                min_investment:Optional[float]=None,max_investment:Optional[float]=None,jurisdiction:str="",maturity:str="",
                u=Depends(require("marketplace:read")),s:Session=Depends(db)):
    q=s.query(Asset).filter(Asset.status=="live")
    if search:q=q.filter((Asset.name.ilike(f"%{search}%"))|(Asset.symbol.ilike(f"%{search}%")))
    if category:q=q.filter(Asset.category==category)
    if min_yield is not None:q=q.filter(Asset.expected_yield>=min_yield)
    if max_yield is not None:q=q.filter(Asset.expected_yield<=max_yield)
    if min_investment is not None:q=q.filter(Asset.minimum_investment>=min_investment)
    if max_investment is not None:q=q.filter(Asset.maximum_investment<=max_investment)
    if jurisdiction:q=q.filter(Asset.jurisdiction==jurisdiction)
    if maturity:q=q.filter(Asset.maturity_date==maturity)
    # Risk is stored on investor suitability in this MVP; asset-level risk can be added as a production field.
    return obj_list(q.order_by(Asset.id.desc()).all())

@app.get("/marketplace/{asset_id}")
def marketplace_detail(asset_id:int,u=Depends(require("marketplace:read")),s:Session=Depends(db)):
    a=s.get(Asset,asset_id)
    if not a or a.status!="live": raise HTTPException(404,"Asset not available")
    tc=s.query(TokenConfig).filter(TokenConfig.asset_id==asset_id).first()
    return {"asset":obj_dict(a),"token":obj_dict(tc) if tc else None,"issuer":{"organization_id":a.organization_id},"compliance_requirements":{"kyc":True,"aml":True,"jurisdiction":a.jurisdiction}}

@app.get("/wallet")
def get_wallet(u=Depends(current_user),s:Session=Depends(db)):
    w=s.query(Wallet).filter(Wallet.user_id==u.id).first()
    if not w: w=Wallet(user_id=u.id,address="0x"+secrets.token_hex(20),whitelisted=u.kyc_status=="approved"); s.add(w); s.commit(); s.refresh(w)
    return obj_dict(w)

@app.get("/wallet/holdings")
def wallet_holdings(u=Depends(current_user),s:Session=Depends(db)):
    w=s.query(Wallet).filter(Wallet.user_id==u.id).first()
    return obj_list(s.query(Holding).filter(Holding.wallet_id==w.id).all()) if w else []

@app.post("/orders")
def invest(x:InvestIn,u=Depends(require("orders:write")),s:Session=Depends(db)):
    if u.role!="investor" or u.kyc_status!="approved": raise HTTPException(400,"Approved investor required")
    a=s.get(Asset,x.asset_id); tc=s.query(TokenConfig).filter(TokenConfig.asset_id==x.asset_id).first()
    if not a or a.status!="live" or not tc: raise HTTPException(400,"Asset unavailable")
    if not (tc.minimum_purchase<=x.amount<=tc.maximum_purchase): raise HTTPException(400,"Investment outside configured limits")
    qty=x.amount/tc.token_price
    o=InvestmentOrder(investor_id=u.id,asset_id=a.id,amount=x.amount,token_quantity=qty,status="pending")
    s.add(o); s.commit(); s.refresh(o); audit(s,u,"CREATE","InvestmentOrder",o.id,f"Amount {x.amount}"); return obj_dict(o)

@app.post("/payments")
def create_payment(x:PaymentIn,u=Depends(require("payments:write")),s:Session=Depends(db)):
    o=s.get(InvestmentOrder,x.order_id)
    if not o or o.investor_id!=u.id: raise HTTPException(404,"Order not found")
    if x.method not in ["bank_transfer","escrow","tokenized_deposit","stablecoin","cbdc","digital_currency","other"]: raise HTTPException(400,"Unsupported payment method")
    p=Payment(order_id=o.id,payer_id=u.id,amount=o.amount,method=x.method,status="validated",reference="PAY-"+secrets.token_hex(8),escrow_locked=True)
    s.add(p); s.commit(); s.refresh(p); o.payment_id=p.id; s.commit(); audit(s,u,"PAYMENT_INITIATED","Payment",p.id,x.method); return obj_dict(p)

@app.post("/settlements/{order_id}/execute")
def settle(order_id:int,u=Depends(require("settlement:write")),s:Session=Depends(db)):
    o=s.get(InvestmentOrder,order_id)
    if not o: raise HTTPException(404,"Order not found")
    if u.role=="investor" and o.investor_id!=u.id: raise HTTPException(403,"You can only settle your own investment order")
    p=s.get(Payment,o.payment_id) if o.payment_id else None
    if not p or p.status!="validated": raise HTTPException(400,"Payment must be validated")
    st=Settlement(order_id=o.id,buyer_id=o.investor_id,seller_id=None,asset_id=o.asset_id,quantity=o.token_quantity,cash_amount=o.amount,status="completed",reconciliation_status="reconciled")
    s.add(st); s.commit(); s.refresh(st)
    w=s.query(Wallet).filter(Wallet.user_id==o.investor_id).first()
    if not w: w=Wallet(user_id=o.investor_id,address="0x"+secrets.token_hex(20),whitelisted=True); s.add(w); s.commit(); s.refresh(w)
    h=s.query(Holding).filter(Holding.wallet_id==w.id,Holding.asset_id==o.asset_id).first()
    if h:h.quantity+=o.token_quantity
    else:s.add(Holding(wallet_id=w.id,asset_id=o.asset_id,quantity=o.token_quantity))
    p.status="completed"; p.escrow_locked=False; o.status="completed"; o.settlement_id=st.id; s.commit()
    audit(s,u,"SETTLE","Settlement",st.id,"DvP completed"); return obj_dict(st)

@app.get("/payments")
def payments(u=Depends(require("payments:read")),s:Session=Depends(db)): return obj_list(s.query(Payment).order_by(Payment.id.desc()).all())

@app.get("/settlements")
def settlements(u=Depends(require("settlement:read")),s:Session=Depends(db)): return obj_list(s.query(Settlement).order_by(Settlement.id.desc()).all())

@app.post("/reconciliation/{settlement_id}")
def reconcile(settlement_id:int,u=Depends(require("settlement:write")),s:Session=Depends(db)):
    st=s.get(Settlement,settlement_id)
    if not st: raise HTTPException(404,"Settlement not found")
    st.reconciliation_status="reconciled"; st.exception_message=""; s.commit(); audit(s,u,"RECONCILE","Settlement",settlement_id,"Reconciled"); return obj_dict(st)

@app.post("/trading/orders")
def create_trade_order(x:TradeIn,u=Depends(require("trading:write")),s:Session=Depends(db)):
    if u.role!="investor": raise HTTPException(403,"Investor required")
    if x.side not in ("buy","sell"): raise HTTPException(400,"Side must be buy or sell")
    a=s.get(Asset,x.asset_id)
    if not a or a.status!="live": raise HTTPException(400,"Asset unavailable")
    if x.side=="sell":
        w=s.query(Wallet).filter(Wallet.user_id==u.id).first(); h=s.query(Holding).filter(Holding.wallet_id==w.id,Holding.asset_id==x.asset_id).first() if w else None
        if not h or h.quantity<x.quantity: raise HTTPException(400,"Insufficient token balance")
    o=TradeOrder(investor_id=u.id,asset_id=x.asset_id,side=x.side,quantity=x.quantity,remaining_quantity=x.quantity,price=x.price,
                 status="submitted",expires_at=datetime.now(timezone.utc)+timedelta(minutes=x.expires_minutes))
    s.add(o); s.commit(); s.refresh(o); audit(s,u,"CREATE","TradeOrder",o.id,f"{x.side} {x.quantity}@{x.price}"); return obj_dict(o)

@app.get("/trading/order-book/{asset_id}")
def order_book(asset_id:int,u=Depends(require("trading:read")),s:Session=Depends(db)):
    now=datetime.now(timezone.utc)
    orders=s.query(TradeOrder).filter(TradeOrder.asset_id==asset_id,TradeOrder.status.in_(["submitted","partially_filled"])).all()
    for o in orders:
        if o.expires_at and o.expires_at.replace(tzinfo=timezone.utc)<now: o.status="expired"
    s.commit()
    buys=sorted([o for o in orders if o.side=="buy" and o.status in ("submitted","partially_filled")],key=lambda z:(-z.price,z.created_at))
    sells=sorted([o for o in orders if o.side=="sell" and o.status in ("submitted","partially_filled")],key=lambda z:(z.price,z.created_at))
    return {"buy":obj_list(buys),"sell":obj_list(sells)}

@app.post("/trading/match/{asset_id}")
def match(asset_id:int,u=Depends(require("trading:write")),s:Session=Depends(db)):
    now=datetime.now(timezone.utc)
    orders=s.query(TradeOrder).filter(TradeOrder.asset_id==asset_id,TradeOrder.status.in_(["submitted","partially_filled"])).all()
    for o in orders:
        if o.expires_at and o.expires_at.replace(tzinfo=timezone.utc)<now: o.status="expired"
    s.commit()
    trades=[]
    while True:
        buys=sorted([o for o in orders if o.side=="buy" and o.remaining_quantity>0 and o.status in ("submitted","partially_filled")],key=lambda z:(-z.price,z.created_at))
        sells=sorted([o for o in orders if o.side=="sell" and o.remaining_quantity>0 and o.status in ("submitted","partially_filled")],key=lambda z:(z.price,z.created_at))
        if not buys or not sells or buys[0].price<sells[0].price: break
        b,sell=buys[0],sells[0]
        qty=min(b.remaining_quantity,sell.remaining_quantity); price=sell.price
        t=Trade(asset_id=asset_id,buy_order_id=b.id,sell_order_id=sell.id,buyer_id=b.investor_id,seller_id=sell.investor_id,quantity=qty,price=price)
        s.add(t); b.remaining_quantity-=qty; sell.remaining_quantity-=qty
        b.status="filled" if b.remaining_quantity==0 else "partially_filled"
        sell.status="filled" if sell.remaining_quantity==0 else "partially_filled"
        s.commit(); s.refresh(t); trades.append(t)
    for t in trades:
        st=Settlement(asset_id=t.asset_id,buyer_id=t.buyer_id,seller_id=t.seller_id,quantity=t.quantity,cash_amount=t.quantity*t.price,status="pending",reconciliation_status="pending")
        s.add(st); s.commit(); s.refresh(st); t.settlement_status="instruction_created"; s.commit()
    audit(s,u,"MATCH","Trade",asset_id,f"{len(trades)} trade(s) generated")
    return {"trades":obj_list(trades),"count":len(trades)}

@app.post("/trading/trades/{trade_id}/settle")
def settle_trade(trade_id:int,u=Depends(require("settlement:write")),s:Session=Depends(db)):
    t=s.get(Trade,trade_id)
    if not t: raise HTTPException(404,"Trade not found")
    if t.settlement_status=="settled": return obj_dict(t)
    sw=s.query(Wallet).filter(Wallet.user_id==t.seller_id).first(); bw=s.query(Wallet).filter(Wallet.user_id==t.buyer_id).first()
    sh=s.query(Holding).filter(Holding.wallet_id==sw.id,Holding.asset_id==t.asset_id).first() if sw else None
    if not sh or sh.quantity<t.quantity: raise HTTPException(400,"Seller no longer has enough tokens")
    if not bw: bw=Wallet(user_id=t.buyer_id,address="0x"+secrets.token_hex(20),whitelisted=True); s.add(bw); s.commit(); s.refresh(bw)
    bh=s.query(Holding).filter(Holding.wallet_id==bw.id,Holding.asset_id==t.asset_id).first()
    sh.quantity-=t.quantity
    if bh: bh.quantity+=t.quantity
    else: s.add(Holding(wallet_id=bw.id,asset_id=t.asset_id,quantity=t.quantity))
    t.settlement_status="settled"; s.commit(); audit(s,u,"SETTLE","Trade",t.id,"Secondary trade settled"); return obj_dict(t)

@app.get("/trading/trades")
def trades(u=Depends(require("trading:read")),s:Session=Depends(db)): return obj_list(s.query(Trade).order_by(Trade.id.desc()).all())

@app.post("/trading/orders/{order_id}/cancel")
def cancel_order(order_id:int,u=Depends(require("trading:write")),s:Session=Depends(db)):
    o=s.get(TradeOrder,order_id)
    if not o or o.investor_id!=u.id: raise HTTPException(404,"Order not found")
    if o.status=="filled": raise HTTPException(400,"Filled order cannot be cancelled")
    o.status="cancelled"; s.commit(); audit(s,u,"CANCEL","TradeOrder",order_id,"Cancelled"); return obj_dict(o)

@app.get("/audit")
def audit_logs(u=Depends(require("audit:read")),s:Session=Depends(db)): return obj_list(s.query(AuditLog).order_by(AuditLog.id.desc()).limit(200).all())
