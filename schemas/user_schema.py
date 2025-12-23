from schemas.imports import *
from pydantic import AliasChoices, Field
import time
from security.hash import hash_password

class UserSignUp(BaseModel):
    firstName:str
    lastName:str    
    email:EmailStr
    password:str | bytes
    
    
class UserLogin(BaseModel):
    email:EmailStr
    password:str | bytes
    
    
class UserBase(BaseModel):
    # Add other fields here 
    firstName:Optional[str]=None
    lastName:Optional[str]=None
    loginType:LoginType
    email:EmailStr
    password:str | bytes
    oauth_access_token:Optional[str]=None
    oauth_refresh_token:Optional[str]=None
    pass

class UserRefresh(BaseModel):
    # Add other fields here 
    refresh_token:str
    pass


class UserCreate(UserBase):
    # Add other fields here
     
    date_created: int = Field(default_factory=lambda: int(time.time()))
    last_updated: int = Field(default_factory=lambda: int(time.time()))
    @model_validator(mode='after')
    def obscure_password(self):
        self.password=hash_password(self.password)
        return self
class UserUpdate(BaseModel):
    # Add other fields here 
    last_updated: int = Field(default_factory=lambda: int(time.time()))

class UserOut(UserBase):
    # Add other fields here 
    id: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices("_id", "id"),
        serialization_alias="id",
    )
    date_created: Optional[int] = None
    accountStatus:Optional[AccountStatus]=AccountStatus.ACTIVE
    last_updated: Optional[int] = None
    refresh_token: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices("refresh_token", "refreshToken"),
        serialization_alias="refreshToken",
    )
    access_token: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices("access_token", "accessToken"),
        serialization_alias="accessToken",
    )
    @model_validator(mode="before")
    @classmethod
    def convert_objectid(cls, values):
        if "_id" in values and isinstance(values["_id"], ObjectId):
            values["_id"] = str(values["_id"])  # coerce to string before validation
        return values
            
    class Config:
        populate_by_name = True  # allows using `id` when constructing the model
        arbitrary_types_allowed = True  # allows ObjectId type
        json_encoders = {
            ObjectId: str  # automatically converts ObjectId → str
        }
        
        
        
        
class UserUpdatePassword(BaseModel):
    password:Optional[str | bytes]=None
    last_updated: int = Field(default_factory=lambda: int(time.time()))
    @model_validator(mode='after')
    def obscure_password(self):
        if self.password:
            self.password=hash_password(self.password)
            return self
        
        