from datetime import timedelta
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
    loginType:Optional[LoginType]=None
    id: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices("_id", "id"),
        serialization_alias="id",
    )
    
    date_created: Optional[int] = Field(
        default=None,
        validation_alias=AliasChoices("date_created", "dateCreated"),
        serialization_alias="dateCreated",
    )
    date_Joined:Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices("date_Joined", "dateJoined"),
        serialization_alias="dateJoined",
    )
    accountStatus:Optional[AccountStatus]=AccountStatus.ACTIVE
    last_updated: Optional[int] = Field(
        default=None,
        validation_alias=AliasChoices("last_updated", "lastUpdated"),
        serialization_alias="lastUpdated",
    )
 
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
    
    
    @model_validator(mode="before")
    @classmethod
    def normalize_date_joined(cls, values):
        date_joined = values.get("date_Joined")
        date_created = values.get("date_created")
        dt = None

        if date_joined is None and date_created is not None:
            dt = datetime.fromtimestamp(date_created, tz=timezone.utc)
        elif isinstance(date_joined, int):
            dt = datetime.fromtimestamp(date_joined, tz=timezone.utc)
        elif isinstance(date_joined, datetime):
            dt = date_joined
        elif isinstance(date_joined, str):
            try:
                dt = datetime.fromisoformat(date_joined.replace("Z", "+00:00"))
            except Exception:
                dt = None

        if dt:
            values["date_Joined"] = dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")

        return values
    
    @model_validator(mode="after")
    @classmethod
    def set_date_joined(cls, model):
        """If date_joined is None, calculate from date_created."""
        
        if model.date_Joined is None and model.date_created is not None:
            # Convert timestamp to UTC datetime
            dt_created = datetime.fromtimestamp(model.date_created, tz=timezone.utc)

            # Example calculation: here we just use the same date_created (adjust as needed)
            dt_joined = dt_created  # or dt_created + timedelta(days=1)

            # Format as ISO 8601 with milliseconds and UTC offset
            model.date_Joined = dt_joined.isoformat(timespec="milliseconds")
        return model
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
        
        