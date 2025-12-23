from bson import ObjectId
from pydantic import GetJsonSchemaHandler
from pydantic import BaseModel, EmailStr, Field,model_validator
from pydantic_core import core_schema
from datetime import datetime,timezone
from typing import Optional,List,Any
from enum import Enum
import time

class UserType(str,Enum):
    member= "member"
   
    admin="admin"

class ResetPasswordInitiation(BaseModel):
    # Add other fields here
    email:EmailStr 
    
class ResetPasswordInitiationResponse(BaseModel):
    # Add other fields here
    resetToken:str
    
    
class ResetPasswordConclusion(BaseModel):
    # Add other fields here
    otp:str
    resetToken:str 
    password:str 
    
class LoginType(str, Enum):
    google = "GOOGLE"
    password = "PASSWORD"
    passwordless="PASSWORDLESS"

class AccountStatus(str, Enum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    SUSPENDED = "SUSPENDED"

class Permission(BaseModel):
    name: str
    methods: List[str]
    path: str
    description: Optional[str] = None

class PermissionList(BaseModel):
    permissions: List[Permission]