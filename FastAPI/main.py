from fastapi import FastAPI, HTTPException, Depends,status, APIRouter, Query
from typing import Annotated, List
from sqlalchemy.orm import Session
from pydantic import BaseModel
from database import SessionLocal, engine
from userbase import SessionLocal_user,uengine
from fastapi.middleware.cors import CORSMiddleware
import models as models
import usermodels as usermodels
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from datetime import datetime, timedelta
from usermodels import User


app = FastAPI()

#SECRET_KEY = "your-secret-key"
#ALGORITHM = "HS256"
#ACCESS_TOKEN_EXPIRE_MINUTES = 30

#oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Function to create an access token
##def create_access_token(data: dict, expires_delta: timedelta = None):
  ##  to_encode = data.copy()
  ##  if expires_delta:
    #    expire = datetime.utcnow() + expires_delta
    #else:
     #   expire = datetime.utcnow() + timedelta(minutes=15)
    #to_encode.update({"exp": expire})
    #encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    #return encoded_jwt

# Dependency to get the current user from the token
#def get_current_user(token: str = Depends(oauth2_scheme)):
 #   credentials_exception = HTTPException(
  #      status_code=status.HTTP_401_UNAUTHORIZED,
  #      detail="Could not validate credentials",
   #     headers={"WWW-Authenticate": "Bearer"},
    #)
    #try:
     #   payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
     #   username: str = payload.get("sub")
      #  if username is None:
       #     raise credentials_exception
        #return UserModel(user_id=1, username=username, password="")  # Replace with actual user retrieval logic
    #except JWTError:
     #   raise credentials_exception
# Handle Cross-Origin Resource Sharing
origins = [
    "*",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*']
)

# Defining Models for Data in/out API
class AnimalBase(BaseModel):
    name: str
    species: str
    age: int
    color: str
    is_adopted: bool

class AnimalModel(AnimalBase):
    id: int

    class Config:
        from_attributes = True
     

# Database Connection Setup
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]

models.Base.metadata.create_all(bind=engine)

class UserBase(BaseModel):
    username: str
    password: str


class UserModel(UserBase):
    user_id: int

    class Config:
        from_attributes = True
     

# Database Connection Setup
def get_userdb():
    userdb = SessionLocal_user()
    try:
        yield userdb
    finally:
        userdb.close()

userdb_dependency = Annotated[Session, Depends(get_userdb)]

usermodels.uBase.metadata.create_all(bind=uengine)

def get_user_details_from_database(userdb: Session, username: str):
    db_user = userdb.query(usermodels.User).filter_by(username=username).first()
    if db_user:
        return {'id': db_user.user_id, 'username': db_user.username, 'password': db_user.password}
    else:
        return None

@app.get("/")
async def root():
    return {"message": "Welcome to the Animal Adoption Platform. Check SWAGGER at http://localhost:8000/docs"}

# Register a new user
@app.post("/register/", response_model=UserModel)
async def register_user(user: UserBase, userdb: userdb_dependency):
    # Check if the password already exists
    existing_password_user = userdb.query(usermodels.User).filter_by(password=user.password).first()
    if existing_password_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password already in use")

    # If the password doesn't exist, proceed with registration
    db_user = usermodels.User(**user.dict())
    userdb.add(db_user)
    userdb.commit()
    userdb.refresh(db_user)
    return db_user

global user_details
user_details = {
    'id': 0,
    'username': 'default',
    'password': 'default'}
# User Login
@app.post("/login/")
async def login_user(user: UserBase, userdb: userdb_dependency):
    db_user = userdb.query(usermodels.User).filter_by(username=user.username, password=user.password).first()
    if db_user:
        global user_details
        user_details = get_user_details_from_database(userdb, username=user.username)
        return {"message": "Login successful"}
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")

# User logout 
@app.get("/logout")
def logout():
    global user_details

    # Update user details on logout
    user_details = {
        'id': 0,
        'username': 'default',
        'password': 'default'
    }

    # Return a message
    return {"message": "User logged out"}



# post a new Animal (accessible only if user_details.id is not 0)
@app.post("/animals/", response_model=AnimalModel)
async def create_animal(animal: AnimalBase, db: db_dependency):
    

    if user_details.get('id') == 0:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permission denied")

    db_animal = models.Animal(**animal.model_dump())
    db.add(db_animal)
    db.commit()
    db.refresh(db_animal)
    return db_animal

# Add a new endpoint to get the password
#@app.post("/enter-password/")
#async def enter_password(password: str):
 #   return {"password": password}

#def get_user_details_from_database(db: Session, user_id: int):
 #   user = db.query(User).filter(User.user_id == user_id).first()
  #  if user:
   #     return {'id': user.user_id, 'username': user.username, 'password': user.password}

# Update the get_current_user function to use the entered password
#def get_current_user(password: str = Query(..., alias="password")):
 #   if password != "0000":
  #      raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect password")

    # Replace with actual user retrieval logic, keeping the original id and username
    # For demonstration purposes, assume you have a function to retrieve the user details from your database
   # user_details = get_user_details_from_database()  # Replace this with your actual logic

    # Assuming user_details is a dictionary containing id, username, and password
    #return UserModel(user_id=user_details['id'], username=user_details['username'], password=user_details['password'])

# Get userbase (only accessible if password is "0000" and user_details.id is not 0)
@app.get("/users/", response_model=List[UserModel])
async def get_userbase(userdb: userdb_dependency):
    # Check if the password is "0000" and user_details.id is not 0
    if user_details.get('password') == "0000" and user_details.get('id') != 0:
        return userdb.query(usermodels.User).all()
    else:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permission denied")

# Show Animals (accessible based on user password and user_details.id is not 0)
@app.get("/animals/", response_model=List[AnimalModel])
async def read_animals(db: db_dependency):
    # Check if user_details.id is 0, deny access
    if user_details.get('id') == 0:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permission denied")

    # Get all animals
    animals = db.query(models.Animal).all()

    # Filter animals based on user password
    filtered_animals = []

    for animal in animals:
        # Check if the password is "0000" or if the animal is not adopted
        if user_details.get('password') == "0000" or not animal.is_adopted:
            filtered_animals.append(animal)

    return filtered_animals

# Update Animal (accessible only if user password is "0000" and user_details.id is not 0)
@app.put("/animals/{animal_id}", response_model=AnimalModel)
async def update_animal(
    animal_id: int,
    animal: AnimalBase,
    db: db_dependency
):

    # Check if the password is "0000" and user_details.id is not 0
    if user_details.get('password') != "0000" or user_details.get('id') == 0:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permission denied")

    # Query the database to get the animal
    db_animal = db.query(models.Animal).filter(models.Animal.id == animal_id).first()

    # Check if the animal exists
    if db_animal:
        # Update the animal attributes
        for key, value in animal.dict().items():
            setattr(db_animal, key, value)

        # Commit changes to the database
        db.commit()
        db.refresh(db_animal)

        return db_animal
    else:
        raise HTTPException(status_code=404, detail="Animal not found")

# Delete Animal by ID (accessible only if user password is "0000" and user_details.id is not 0)
@app.delete("/animals/{animal_id}", response_model=AnimalModel)
async def delete_animal(animal_id: int, db: db_dependency):

    # Check if the password is "0000" and user_details.id is not 0
    if user_details.get('password') != "0000" or user_details.get('id') == 0:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permission denied")

    # Query the database to get the animal
    db_animal = db.query(models.Animal).filter(models.Animal.id == animal_id).first()

    # Check if the animal exists
    if db_animal:
        # Delete the animal from the database
        db.delete(db_animal)
        db.commit()

        return db_animal
    else:
        raise HTTPException(status_code=404, detail="Animal not found")

    
# Get Animal by ID (accessible if the animal is not adopted or user password is "0000")
# Get Animal by ID (accessible only if user password is "0000" and user_details.id is not 0)
@app.get("/animals/{animal_id}", response_model=AnimalModel)
async def read_animal(animal_id: int, db: db_dependency):

    # Query the database to get the animal
    db_animal = db.query(models.Animal).filter(models.Animal.id == animal_id).first()

    # Check if the animal exists
    if db_animal:
        # Check if the password is "0000" or if the animal is not adopted
        if user_details.get('password') == "0000" or not db_animal.is_adopted:
            return db_animal
        elif user_details.get('id') == 0:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permission denied")
        else:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permission denied")
    else:
        raise HTTPException(status_code=404, detail="Animal not found")

def get_all_users(db: Session):
    return db.query(usermodels.User).all()

# Adopt Animal (accessible only if user_details.id is not 0)
@app.put("/adopt/{animal_id}")
async def adopt_animal(animal_id: int, db: db_dependency):
    # Check if user_details.id is not 0
    if user_details.get('id') != 0:
        db_animal = db.query(models.Animal).filter(models.Animal.id == animal_id).first()

        if db_animal:
            if not db_animal.is_adopted:
                db_animal.is_adopted = True
                db.commit()
                db.refresh(db_animal)
                return {"message": f"Animal with ID {animal_id} has been adopted!"}
            else:
                raise HTTPException(status_code=400, detail="Animal is already adopted.")
        else:
            raise HTTPException(status_code=404, detail="Animal not found.")
    else:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permission denied")

    
# Delete User by ID (accessible only if user ID matches or user password is "0000")
@app.delete("/users/{user_id}", response_model=UserModel)
async def delete_user(user_id: int, userdb: userdb_dependency):

    # Check if the user ID matches or if the password is "0000" and user_details.id is different from 0
    if (user_details.get('id') == user_id or user_details.get('password') == "0000") and user_details.get('id') != 0:
        # Query the database to get the user
        db_user = userdb.query(usermodels.User).filter(usermodels.User.user_id == user_id).first()

        # Check if the user exists
        if db_user:
            # Delete the user from the database
            userdb.delete(db_user)
            userdb.commit()

            return db_user
        else:
            raise HTTPException(status_code=404, detail="User not found")
    else:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permission denied")




