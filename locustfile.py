from locust import HttpUser, TaskSet, task, between
import random
from datetime import datetime, timedelta
import jwt
import os

jwt_secret = os.getenv('JWT_SECRET')
jwt_algorithm = os.getenv('JWT_ALGORITHM')

class UserBehavior(TaskSet):

    def on_start(self):
    # Set up test account details
        self.user_id = 'f651f542-3734-43f2-a6d8-9f1981856629'
        self.child_id = 61
        self.question_id = 1
        self.correct_answer = 1

        jwt_body = {"userId": self.user_id,
                    "exp": datetime.now() + timedelta(minutes=60)}
        self.jwt_token = jwt.encode(jwt_body, jwt_secret, algorithm=jwt_algorithm)
        self.request_headers = {
            'Authorization': f'Bearer {self.jwt_token}',
            'Content-Type': 'application/json; charset=UTF-8'
        }


    @task(1)
    def validate_token(self):
        self.client.post("/validate-token", json={"token": self.jwt_token})

    @task(1)
    def get_children(self):
        self.client.get(url=f"/child/{self.user_id}", headers=self.request_headers)

    @task(3)
    def add_result(self):
        result_data = {
            "childId": self.child_id,
            "sessionStartTime": "2024-09-01T12:00:00",
            "questionId": 1,
            "correctAnswer": 1,
            "selectedAnswer": random.randint(0, 1),
            "timeTaken": random.randint(1000, 4000)
        }
        self.client.post("/result", json=result_data)

class WebsiteUser(HttpUser):
    tasks = [UserBehavior]
    wait_time = between(2, 3)
