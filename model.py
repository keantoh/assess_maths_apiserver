from uuid import uuid4
from sqlalchemy import Column, String, Boolean, Date, ForeignKey, Integer, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from pydantic import BaseModel
from datetime import datetime, date

Base = declarative_base()

# SQLAlchemy: Handles database interactions, defines database schemas, and performs CRUD operations.
# Pydantic: Manages data validation, defines request and response schemas, and ensures data integrity

class User(Base):
    __tablename__ = 'User'
    userId = Column('user_id', String, primary_key=True, default=lambda: str(uuid4()))
    email = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    firstName = Column('first_name', String, nullable=False)
    lastName = Column('last_name', String, nullable=False)
    country = Column(String, nullable=False)
    isAdmin = Column('is_admin', Boolean, default=False)
    passwordToken = Column('password_token', String)
    tokenExpiry = Column('token_expiry', DateTime)
    isActive = Column('is_active', Boolean, nullable=False, default=True)
    createdAt = Column('created_at', DateTime, nullable=False, default=datetime.now)
    updatedAt = Column('updated_at', DateTime)

class UserCreate(BaseModel):
    email: str
    password: str
    firstName: str
    lastName: str
    country: str
    isAdmin: bool = False

class UserLogin(BaseModel):
    email: str
    password: str

class UserLoginResponse(BaseModel):
    userId: str
    email: str
    firstName: str 
    lastName: str
    country: str
    isAdmin: bool 
    isActive: bool
    token: str

class UserToken(BaseModel):
    token: str

class UserDetailsUpdate(BaseModel):
    email: str
    firstName: str
    lastName: str
    country: str
    isAdmin: bool = False

class UserPasswordChange(BaseModel):
    password: str
    newPassword: str

class UserEmail(BaseModel):
    email: str

class UserPasswordUpdate(BaseModel):
    email: str
    token: str
    newPassword: str

class UserSearchResponse(BaseModel):
    userId: str
    email: str
    firstName: str 
    lastName: str
    country: str
    isAdmin: bool 
    isActive: bool
    createdAt: datetime

class UserDelete(BaseModel):
    userId: str
    password: str

class Colour(Base):
    __tablename__ = 'Colour'
    colourId = Column('colour_id', Integer, primary_key=True)
    colourName = Column('colour_name', String, nullable=False)

class Animal(Base):
    __tablename__ = 'Animal'
    animalId = Column('animal_id', Integer, primary_key=True)
    animalName = Column('animal_name', String, nullable=False)


class Child(Base):
    __tablename__ = 'Child'
    childId = Column('child_id', Integer, primary_key=True)
    parentId = Column('parent_id', String, ForeignKey('User.user_id'))
    name = Column(String, nullable=False)
    gender = Column(String, nullable=False)
    dob = Column(Date, nullable=False)
    favColour = Column('fav_colour', Integer, ForeignKey('Colour.colour_id'), nullable=False)
    favAnimal = Column('fav_animal', Integer, ForeignKey('Animal.animal_id'), nullable=False)
    colourName = relationship('Colour', primaryjoin='Child.favColour == Colour.colourId', uselist=False)
    animalName = relationship('Animal', primaryjoin='Child.favAnimal == Animal.animalId', uselist=False)

class ChildCreate(BaseModel):
    parentId: str
    name: str
    gender: str
    dob: date
    favColour: int
    favAnimal: int


class ChildResponse(BaseModel):
    childId: int
    name: str
    gender: str
    dob: date
    favColour: int
    favAnimal: int

    class Config:
        orm_mode = True

class Question(Base):
    __tablename__ = 'Question'
    questionId = Column('question_id', Integer, primary_key=True, autoincrement=True)
    categoryId = Column('category_id', Integer, nullable=False)
    difficultyLevel = Column('difficulty_level', Integer, nullable=False)
    text = Column(String, nullable=False)

class Result(Base):
    __tablename__ = 'Result'
    resultId = Column('result_id', String, primary_key=True, default=lambda: str(uuid4()))
    childId = Column('child_id', Integer, ForeignKey('Child.child_id'), nullable=True)
    sessionStartTime = Column('session_start_time', DateTime, nullable=False)
    questionId = Column('question_id', Integer, ForeignKey('Question.question_id'), nullable=False)
    correctAnswer = Column('correct_answer', Integer, nullable=False)
    selectedAnswer = Column('selected_answer', Integer, nullable=False)
    timeTaken = Column('time_taken', Integer, nullable=False)

class ResultCreate(BaseModel):
    childId: int
    sessionStartTime: datetime
    questionId: int
    correctAnswer: int
    selectedAnswer: int
    timeTaken: int

class SearchQuery(BaseModel):
    query: str

class DeleteUser(BaseModel):
    userId: str

class EmailSchema(BaseModel):
    email: str
    subject: str
    body: str