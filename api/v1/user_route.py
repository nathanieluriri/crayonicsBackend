
import re
from fastapi import APIRouter, HTTPException, Query, Request, status, Path,Depends
from typing import List

from fastapi.responses import RedirectResponse

from schemas.imports import ResetPasswordConclusion, ResetPasswordInitiation, ResetPasswordInitiationResponse
from schemas.response_schema import APIResponse
from schemas.tokens_schema import accessTokenOut
from schemas.user_schema import (
    UserCreate,
    UserLogin,
    UserOut,
    UserBase,
    UserSignUp,
    UserUpdate,
    UserRefresh,
    LoginType,
    UserUpdatePassword,
)
from services.user_service import (
    add_user,
    remove_user,
    retrieve_users,
    authenticate_user,
    retrieve_user_by_user_id,
    update_user,
    update_user_by_id,
    logout_user as logout_user_service,
    refresh_user_tokens_reduce_number_of_logins,
    oauth,
    user_reset_password_conclusion,
    user_reset_password_intiation
)
from security.auth import verify_token_to_refresh,verify_token_user_role
import os
from dotenv import load_dotenv
load_dotenv()



router = APIRouter(prefix="/users", tags=["Users"])

SUCCESS_PAGE_URL = os.getenv("SUCCESS_PAGE_URL", "http://localhost:5173/success")
ERROR_PAGE_URL   = os.getenv("ERROR_PAGE_URL",   "http://localhost:5173/error")

# --- Step 1: Redirect user to Google login ---
@router.get("/google/auth")
async def login_with_google_account(request: Request):
    redirect_uri = str(request.url_for("auth_callback_user"))

    # Force https
    redirect_uri = re.sub(r"^http://", "https://", redirect_uri)

    print("REDIRECT URI:", redirect_uri)
    return await oauth.google.authorize_redirect(request, redirect_uri)

# --- Step 2: Handle callback from Google ---

@router.get("/auth/callback")
async def auth_callback_user(request: Request):
    token = await oauth.google.authorize_access_token(request)
    user_info = token.get('userinfo')
    google_access_token = token.get("access_token")
    google_refresh_token = token.get("refresh_token")
    # Just print or return user info for now
    if user_info:
        print("✅ Google user info:", user_info)
        
        rider = UserBase(firstName=user_info['name'],password='',lastName=user_info['given_name'],email=user_info['email'],loginType=LoginType.google,oauth_access_token= google_access_token,oauth_refresh_token= google_refresh_token)
        data = await authenticate_user(user_data=rider)
        if data==None:
            new_rider = UserCreate(**rider.model_dump())
            items = await add_user(user_data=new_rider)
            
            access_token = items.access_token
            refresh_token = items.refresh_token
            success_url = f"{SUCCESS_PAGE_URL}?access_token={access_token}&refresh_token={refresh_token}"
            return RedirectResponse(
            url=success_url,
            status_code=status.HTTP_302_FOUND
        )
        access_token = data.access_token
        refresh_token = data.refresh_token

         

        success_url = f"{SUCCESS_PAGE_URL}?access_token={access_token}&refresh_token={refresh_token}"

        return RedirectResponse(
            url=success_url,
            status_code=status.HTTP_302_FOUND
        )
    else:
        raise HTTPException(status_code=400,detail={"status": "failed", "message": "No user info found"})

@router.get("/",response_model_exclude={"data": {"__all__": {"password"}}}, response_model=APIResponse[List[UserOut]],response_model_exclude_none=True,dependencies=[Depends(verify_token_user_role)])
async def list_users(start:int= 0, stop:int=100):
    items = await retrieve_users(start=0,stop=100)
    return APIResponse(status_code=200, data=items, detail="Fetched successfully")

@router.get("/me", response_model_exclude={"data": {"password"}},response_model=APIResponse[UserOut],dependencies=[Depends(verify_token_user_role)],response_model_exclude_none=True)
async def get_my_users(token:accessTokenOut = Depends(verify_token_user_role)):
    items = await retrieve_user_by_user_id(id=token.userId)
    return APIResponse(status_code=200, data=items, detail="users items fetched")



@router.post("/signup", response_model_exclude={"data": {"password"}},response_model=APIResponse[UserOut])
async def signup_new_user(user_data:UserSignUp):
    
    new_user = UserCreate(**user_data.model_dump(),loginType=LoginType.password)
    items = await add_user(user_data=new_user)
    return APIResponse(status_code=200, data=items, detail="Fetched successfully")


@router.post("/login",response_model_exclude={"data": {"password"}}, response_model=APIResponse[UserOut])
async def login_user(user_data:UserLogin):
    user_data=UserBase(**user_data.model_dump(),loginType=LoginType.password)
    items = await authenticate_user(user_data=user_data)
    return APIResponse(status_code=200, data=items, detail="Fetched successfully")


@router.post("/refresh",response_model_exclude={"data": {"password"}},response_model=APIResponse[UserOut],dependencies=[Depends(verify_token_to_refresh)])
async def refresh_user_tokens(user_data:UserRefresh,token:accessTokenOut = Depends(verify_token_to_refresh)):
    
    items= await refresh_user_tokens_reduce_number_of_logins(user_refresh_data=user_data,expired_access_token=token.accesstoken)

    return APIResponse(status_code=200, data=items, detail="users items fetched")


@router.post("/logout")
async def logout_user(
    token: accessTokenOut = Depends(verify_token_user_role),
):
    """
    Logs out the currently authenticated admin.

    This action invalidates the admin’s active session(s) by
    revoking refresh tokens and/or marking tokens as unusable.

    **Authorization:**  
    Requires a valid Access Token in the  
    `Authorization: Bearer <token>` header.
    """

    await logout_user_service(user_id=token.userId)

    return APIResponse(
        status_code=status.HTTP_200_OK,
        data=None,
        detail="Logged out successfully",
    )



@router.delete("/account",dependencies=[Depends(verify_token_user_role)])
async def delete_user_account(token:accessTokenOut = Depends(verify_token_user_role)):
    result = await remove_user(user_id=token.userId)
    return result




 
# -----------------------------------
# ------- PASSWORD MANAGEMENT ------- 
# -----------------------------------

 
@router.patch("/password-reset",dependencies=[Depends(verify_token_user_role)])
async def update_driver_password_while_logged_in(driver_details:UserUpdatePassword,token:accessTokenOut = Depends(verify_token_user_role)):
    driver =  await update_user_by_id(driver_id=token.userId,driver_data=driver_details,is_password_getting_changed=True)
    return APIResponse(data = driver,status_code=200,detail="Successfully updated profile")



@router.post("/password-reset/request",response_model=APIResponse[ResetPasswordInitiationResponse] )
async def start_password_reset_process_for_driver_that_forgot_password(driver_details:ResetPasswordInitiation):
    driver =  await user_reset_password_intiation(user_details=driver_details)   
    return APIResponse(data = driver,status_code=200,detail="Successfully updated profile")



@router.patch("/password-reset/confirm")
async def finish_password_reset_process_for_driver_that_forgot_password(driver_details:ResetPasswordConclusion):
    driver =  await user_reset_password_conclusion(driver_details)
    return APIResponse(data = driver,status_code=200,detail="Successfully updated profile")
