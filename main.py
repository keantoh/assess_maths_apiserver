import random
import string
from fastapi import FastAPI, HTTPException, Depends, Request, status
import jwt
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError, SQLAlchemyError, OperationalError
from passlib.context import CryptContext
from database import get_db
from email_service import send_email
from model import Child, ChildCreate, ChildResponse, DeleteUser, Result, SearchQuery, User, UserCreate, UserDelete, UserDetailsUpdate, UserEmail, UserLogin, UserLoginResponse, UserPasswordChange, UserPasswordUpdate, UserSearchResponse, UserToken, ResultCreate
from typing import List
from datetime import datetime, timedelta
import logging
import os
from dotenv import load_dotenv

app = FastAPI()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
load_dotenv()
jwt_secret = os.getenv('JWT_SECRET')
jwt_algorithm = os.getenv('JWT_ALGORITHM')
jwt_expire_minutes = int(os.getenv('JWT_EXPIRE_MINUTES'))

logging.basicConfig(level=logging.INFO)

def get_user_id_from_request(request: Request):
    try:
        authorization_header = request.headers.get("Authorization")
        if authorization_header is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authorization header missing")

        token_prefix, token = authorization_header.split(" ", 1)
        if token_prefix.lower() != "bearer":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token prefix")
        
        payload = jwt.decode(token, jwt_secret, algorithms=[jwt_algorithm])
        user_id = payload.get("userId")
        return user_id
    
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

@app.post("/signup", status_code=status.HTTP_201_CREATED)
async def signup(user: UserCreate, db: Session = Depends(get_db)):
    try:
        hashed_password = pwd_context.hash(user.password)
        new_user = User(
            email=user.email,
            password=hashed_password,
            firstName=user.firstName,
            lastName=user.lastName,
            country=user.country,
            isAdmin=user.isAdmin
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        jwt_body = {"userId": new_user.userId, "exp": datetime.now() + timedelta(minutes=jwt_expire_minutes)}
        encoded_jwt = jwt.encode(jwt_body, jwt_secret, algorithm=jwt_algorithm)

        logging.info(f"Signup successful: User {new_user.email} (ID: {new_user.userId}).")

        return {
            "userId": new_user.userId,
            "email": new_user.email,
            "firstName": new_user.firstName,
            "lastName": new_user.lastName,
            "country": new_user.country,
            "isAdmin": new_user.isAdmin,
            "isActive": new_user.isActive,
            "token": encoded_jwt
        }
    except IntegrityError as e: 
        db.rollback()
        logging.error(f"Integrity error occurred: {e}")
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Integrity error: Possible constraint violation")

    except OperationalError as e:
        db.rollback()
        logging.error(f"Operational error occurred: {e}")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database operational error")

    except ValueError as e:
        db.rollback()
        logging.error(f"Value error occurred: {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    except Exception as e:
        db.rollback()
        logging.error(f"An unexpected error occurred: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred")

@app.post("/login", response_model=UserLoginResponse, status_code=status.HTTP_200_OK)
async def login(user: UserLogin, db: Session = Depends(get_db)):
    try:
        retrieved_user = db.query(User).filter(User.email == user.email).one_or_none()
        if retrieved_user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invalid credentials")

        if not pwd_context.verify(user.password, retrieved_user.password):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invalid credentials")
        
        jwt_body = {"userId": retrieved_user.userId, "exp": datetime.now() + timedelta(minutes=jwt_expire_minutes)}
        encoded_jwt = jwt.encode(jwt_body, jwt_secret, algorithm=jwt_algorithm)

        logging.info(f"Login successful: User {retrieved_user.email} (ID: {retrieved_user.userId}).")

        return {
            "userId": retrieved_user.userId,
            "email": retrieved_user.email,
            "firstName": retrieved_user.firstName,
            "lastName": retrieved_user.lastName,
            "country": retrieved_user.country,
            "isAdmin": retrieved_user.isAdmin,
            "isActive": retrieved_user.isActive,
            "token": encoded_jwt
        }
    except HTTPException as http_exc:
        logging.error(http_exc)
        raise http_exc
    except OperationalError as e:
        db.rollback()
        logging.error(f"Operational error occurred: {e}")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database operational error")
    except SQLAlchemyError as db_exc:
        logging.error("Database error: %s", str(db_exc))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database error")

    except Exception as e:
        logging.error("Unexpected error: %s", str(e))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
    
@app.post("/validate-token", response_model=UserLoginResponse, status_code=status.HTTP_200_OK)
async def validate_token(request: UserToken, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(request.token, jwt_secret, algorithms=[jwt_algorithm])
        user_id = payload.get("userId")
        retrieved_user = db.query(User).filter(User.userId == user_id).one_or_none()
        
        if retrieved_user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        return {
            "userId": retrieved_user.userId,
            "email": retrieved_user.email,
            "firstName": retrieved_user.firstName,
            "lastName": retrieved_user.lastName,
            "country": retrieved_user.country,
            "isAdmin": retrieved_user.isAdmin,
            "isActive": retrieved_user.isActive,
            "token": request.token
        }
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    except HTTPException as http_exc:
        raise http_exc
    except OperationalError as e:
        db.rollback()
        logging.error(f"Operational error occurred: {e}")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database operational error")
    except SQLAlchemyError as db_exc:
        logging.error("Database error: %s", str(db_exc))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database error")

    except Exception as e:
        logging.error("Unexpected error: %s", str(e))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
    
@app.put("/update_user_details/{userId}", status_code=status.HTTP_200_OK)
async def update_user_details(request: Request, userId: str, user: UserDetailsUpdate, db: Session = Depends(get_db)):
    try:
        token_user_id = get_user_id_from_request(request)
        if token_user_id != userId:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        db_user = db.query(User).filter(User.userId == userId).first()
    
        if not db_user:
            raise HTTPException(status_code=404, detail="User not found")
        db_user.email = user.email
        db_user.firstName = user.firstName
        db_user.lastName = user.lastName
        db_user.country = user.country
        db_user.updatedAt = datetime.now()
        db.commit()

        logging.info(f"Update user successful: User {db_user.email} (ID: {db_user.userId}).")

        return {"detail": "User updated successfully"}
    except IntegrityError as e: 
        db.rollback()
        logging.error(f"Integrity error occurred: {e}")
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Integrity error: Possible constraint violation")

    except OperationalError as e:
        db.rollback()
        logging.error(f"Operational error occurred: {e}")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database operational error")

    except ValueError as e:
        db.rollback()
        logging.error(f"Value error occurred: {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    
    except HTTPException as http_exc:
        raise http_exc

    except Exception as e:
        db.rollback()
        logging.error(f"An unexpected error occurred: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred")
    
@app.put("/change_user_password/{userId}", status_code=status.HTTP_200_OK)
async def change_user_password(userId: str, user: UserPasswordChange, db: Session = Depends(get_db)):
    try:
        retrieved_user = db.query(User).filter(User.userId == userId).first()

        if retrieved_user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        if not pwd_context.verify(user.password, retrieved_user.password):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password")
        
        new_hashed_password = pwd_context.hash(user.newPassword)
        retrieved_user.password = new_hashed_password
        retrieved_user.updatedAt = datetime.now()
        db.commit()

        logging.info(f"Changed password successful: ID {userId}.")

        return {"detail": "Password changed successfully"}

    except OperationalError as e:
        db.rollback()
        logging.error(f"Operational error occurred: {e}")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database operational error")

    except ValueError as e:
        db.rollback()
        logging.error(f"Value error occurred: {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    
    except HTTPException as http_exc:
        raise http_exc

    except Exception as e:
        db.rollback()
        logging.error(f"An unexpected error occurred: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred")
    
@app.put("/send_password_token", status_code=status.HTTP_200_OK)
async def send_password_token(userEmail: UserEmail, db: Session = Depends(get_db)):
    try:
        email = userEmail.email
        retrieved_user = db.query(User).filter(User.email == email).first()

        if retrieved_user is None:
            return {"detail": "Token sent if email exists"}

        reset_token = ''.join(random.choices(string.ascii_uppercase, k=8))
        reset_token_expiry = datetime.now() + timedelta(minutes=30)

        retrieved_user.passwordToken = reset_token
        retrieved_user.tokenExpiry = reset_token_expiry
        db.commit()

        subject = "Password Reset Request"
        text = f"Hi, please use the following token to reset your password: {reset_token}"

        send_email(subject, text, email)

        logging.info(f"Reset token sent successful: User {userEmail.email}.")

        return {"detail": "Token sent if email exists"}

    except OperationalError as e:
        db.rollback()
        logging.error(f"Operational error occurred: {e}")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database operational error")

    except ValueError as e:
        db.rollback()
        logging.error(f"Value error occurred: {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    
    except HTTPException as http_exc:
        raise http_exc

    except Exception as e:
        db.rollback()
        logging.error(f"An unexpected error occurred: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred")
    
@app.put("/update_user_password", status_code=status.HTTP_200_OK)
async def update_user_password(user: UserPasswordUpdate, db: Session = Depends(get_db)):
    try:
        retrieved_user = db.query(User).filter(User.email == user.email).first()

        if retrieved_user is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email/token")
        
        if retrieved_user.passwordToken != user.token or datetime.now() > retrieved_user.tokenExpiry:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email/token")
        
        new_hashed_password = pwd_context.hash(user.newPassword)
        retrieved_user.password = new_hashed_password
        retrieved_user.passwordToken = None
        retrieved_user.tokenExpiry = None
        retrieved_user.updatedAt = datetime.now()
        db.commit()

        logging.info(f"Password changed successful: User {retrieved_user.email} (ID: {retrieved_user.userId}).")

        return {"detail": "Password changed successfully"}

    except OperationalError as e:
        db.rollback()
        logging.error(f"Operational error occurred: {e}")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database operational error")

    except ValueError as e:
        db.rollback()
        logging.error(f"Value error occurred: {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    
    except HTTPException as http_exc:
        raise http_exc

    except Exception as e:
        db.rollback()
        logging.error(f"An unexpected error occurred: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred")

@app.post("/delete_user_account", status_code=status.HTTP_200_OK)
async def deleteUserAccount(user: UserDelete, db: Session = Depends(get_db)):
    try:
        retrieved_user = db.query(User).filter(User.userId == user.userId).one_or_none()
        if retrieved_user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        if not pwd_context.verify(user.password, retrieved_user.password):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password")
        
        db.query(User).filter(User.userId == user.userId).delete()
        db.commit()

        logging.info(f"Account delete successful: User {retrieved_user.email} (ID: {retrieved_user.userId}).")

        return {"detail": "Account delete successfully"}

    except HTTPException as http_exc:
        raise http_exc
    except OperationalError as e:
        db.rollback()
        logging.error(f"Operational error occurred: {e}")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database operational error")
    except SQLAlchemyError as db_exc:
        logging.error("Database error: %s", str(db_exc))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database error")
    except Exception as e:
        logging.error("Unexpected error: %s", str(e))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
    
@app.post("/search_users", response_model=List[UserSearchResponse], status_code=status.HTTP_200_OK)
async def login(request: Request, searchQuery: SearchQuery, db: Session = Depends(get_db)):
    try:
        user_id = get_user_id_from_request(request)
        user = db.query(User).filter(User.userId == user_id).one_or_none()
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
        query = searchQuery.query.lower()

        users = db.query(User).filter(
            (User.email.ilike(f'%{query}%')) |
            (User.firstName.ilike(f'%{query}%')) |
            (User.lastName.ilike(f'%{query}%'))
        ).limit(20).all()

        if not users:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No users found")

        user_responses = [
            UserSearchResponse(
                userId=user.userId,
                email=user.email,
                firstName=user.firstName,
                lastName=user.lastName,
                country=user.country,
                isAdmin=user.isAdmin,
                isActive=user.isActive,
                createdAt=user.createdAt
            )
            for user in users
        ]

        return user_responses
    
    except HTTPException as http_exc:
        raise http_exc
    except OperationalError as e:
        db.rollback()
        logging.error(f"Operational error occurred: {e}")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database operational error")
    except SQLAlchemyError as db_exc:
        logging.error("Database error: %s", str(db_exc))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database error")
    except Exception as e:
        logging.error("Unexpected error: %s", str(e))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
    

@app.post("/delete_user", status_code=status.HTTP_200_OK)
async def login(request: Request, user: DeleteUser, db: Session = Depends(get_db)):
    try:
        user_id = get_user_id_from_request(request)
        user = db.query(User).filter(User.userId == user_id).one_or_none()
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        
        retrieved_user = db.query(User).filter(User.userId == user.userId).one_or_none()
        if retrieved_user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        
        db.query(User).filter(User.userId == user.userId).delete()
        db.commit()

        logging.info(f"User delete successful: User {retrieved_user.email} (ID: {retrieved_user.userId}).")

        return {"detail": "User delete successfully"}
    
    except HTTPException as http_exc:
        raise http_exc
    except OperationalError as e:
        db.rollback()
        logging.error(f"Operational error occurred: {e}")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database operational error")
    except SQLAlchemyError as db_exc:
        logging.error("Database error: %s", str(db_exc))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database error")

    except Exception as e:
        logging.error("Unexpected error: %s", str(e))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
    
@app.post("/child", response_model=ChildResponse, status_code=status.HTTP_201_CREATED)
async def add_child(request: Request, child: ChildCreate, db: Session = Depends(get_db)):
    try:
        user_id = get_user_id_from_request(request)
        user = db.query(User).filter(User.userId == user_id).one_or_none()
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        
        new_child = Child(
            parentId=child.parentId,
            name=child.name,
            gender=child.gender,
            dob=child.dob,
            favColour=child.favColour,
            favAnimal=child.favAnimal
        )
        db.add(new_child)
        db.commit()

        db.refresh(new_child)

        response_child = ChildResponse(
            childId=new_child.childId,
            name=new_child.name,
            gender=new_child.gender,
            dob=new_child.dob,
            favColour=new_child.favColour,
            favAnimal=new_child.favAnimal
        )
        logging.info(f"Child add successful: ID {new_child.parentId} (Name: {response_child.name}) (ChildID: {response_child.childId}).")

        return response_child
    except IntegrityError as e:
        db.rollback()
        logging.error(f"Integrity error occurred: {e}")
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Integrity error: Possible constraint violation")

    except OperationalError as e:
        db.rollback()
        logging.error(f"Operational error occurred: {e}")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database operational error")

    except ValueError as e:
        db.rollback()
        logging.error(f"Value error occurred: {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        db.rollback()
        logging.error(f"An unexpected error occurred: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred")
    
@app.get("/child/{userId}", response_model=List[ChildResponse], status_code=status.HTTP_200_OK)
async def get_children(request: Request, userId: str, db: Session = Depends(get_db)):
    try:
        user_id = get_user_id_from_request(request)
        user = db.query(User).filter(User.userId == user_id).one_or_none()
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        
        children = db.query(Child).filter(Child.parentId == userId).all()
        if not children:
            return []
        logging.info(f"Child retrieve successful: User {user.email} (ID: {user.userId}).")

        return [ChildResponse.from_orm(child) for child in children]
    except Exception as e:
        logging.error("Unexpected error: %s", str(e))
        raise HTTPException(status_code=500, detail=str(e))
    
@app.put("/update_child/{childId}", status_code=status.HTTP_200_OK)
async def update_child(request: Request, childId: int, child: ChildResponse, db: Session = Depends(get_db)):
    try:
        user_id = get_user_id_from_request(request)
        user = db.query(User).filter(User.userId == user_id).one_or_none()
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        
        db_child = db.query(Child).filter(Child.childId == childId).first()
    
        if not db_child:
            raise HTTPException(status_code=404, detail="Child not found")
        db_child.name = child.name
        db_child.gender = child.gender
        db_child.dob = child.dob
        db_child.favAnimal = child.favAnimal
        db_child.favColour = child.favColour
        db.commit()

        logging.info(f"Child update successful: Child {child.name} (ChildID: {child.childId}).")

        return {"detail": "Child updated successfully"}
    except OperationalError as e:
        db.rollback()
        logging.error(f"Operational error occurred: {e}")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database operational error")

    except ValueError as e:
        db.rollback()
        logging.error(f"Value error occurred: {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    
    except HTTPException as http_exc:
        raise http_exc

    except Exception as e:
        db.rollback()
        logging.error(f"An unexpected error occurred: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred")
    
@app.delete("/delete_child/{childId}", status_code=status.HTTP_200_OK)
async def delete_child(request: Request, childId: int, db: Session = Depends(get_db)):
    try:
        user_id = get_user_id_from_request(request)
        user = db.query(User).filter(User.userId == user_id).one_or_none()
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        
        db_child = db.query(Child).filter(Child.childId == childId).first()
    
        if not db_child:
            raise HTTPException(status_code=404, detail="Child not found")
        db.query(Child).filter(Child.childId == childId).delete()
        db.commit()

        logging.info(f"Child delete successful: ID {user_id} (ChildID: {childId}).")

        return {"detail": "Child deleted successfully"}
    except OperationalError as e:
        db.rollback()
        logging.error(f"Operational error occurred: {e}")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database operational error")

    except ValueError as e:
        db.rollback()
        logging.error(f"Value error occurred: {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    
    except HTTPException as http_exc:
        raise http_exc

    except Exception as e:
        db.rollback()
        logging.error(f"An unexpected error occurred: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred")
    

@app.post("/result", status_code=status.HTTP_201_CREATED)
async def add_result(result: ResultCreate, db: Session = Depends(get_db)):
    try:
        new_result = Result(
            childId=result.childId,
            sessionStartTime=result.sessionStartTime,
            questionId=result.questionId,
            correctAnswer=result.correctAnswer,
            selectedAnswer=result.selectedAnswer,
            timeTaken=result.timeTaken
        )
        db.add(new_result)
        db.commit()

        logging.info(f"Result add successful: ChildID {result.childId} (QuestionID: {result.questionId}).")

        return {"detail": "Result added successfully"}
    except HTTPException as http_exc:
        raise http_exc
    except OperationalError as e:
        db.rollback()
        logging.error(f"Operational error occurred: {e}")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database operational error")
    except SQLAlchemyError as db_exc:
        logging.error("Database error: %s", str(db_exc))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database error")

    except Exception as e:
        logging.error("Unexpected error: %s", str(e))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))