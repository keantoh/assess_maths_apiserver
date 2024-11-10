# ASSESS Maths API Server

The ASSESS Maths API Server provides the back-end services for the ASSESS Maths mobile app. It is built using **FastAPI** for handling HTTP requests, with integration for user authentication, database management, and email functionality.

## Getting Started
1. Clone the repository
2. Create a .env file in the project folder with the necessary environment variables.
3. Create a virtual environment by running "python -m venv myenv".
4. Activate the virtual environment by running "venv\Scripts\activate" on Windows or "source myenv/bin/activate" on macOS/Linux.
5. Install all packages by running "pip install -r requirements.txt".
6. Run "uvicorn main:app --host 0.0.0.0 --port 8000" to start the server locally.
