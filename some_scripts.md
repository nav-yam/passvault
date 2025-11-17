# Run server

   cd server
   node index.js

# Run Client
   cd client
   npm start


# Test registeration
   curl -X POST http://localhost:3000/api/register \
     -H "Content-Type: application/json" \
     -d '{"username":"testuser2","password":"password123"}'

# Test login
   curl -X POST http://localhost:3000/api/login \
     -H "Content-Type: application/json" \
     -d '{"username":"testuser2","password":"password123"}'

# Test protected routes 
   curl http://localhost:3000/api/items

dummy_user_jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEsInVzZXJuYW1lIjoidGVzdHVzZXIyIiwiaWF0IjoxNzYzNDAyNDU0LCJleHAiOjE3NjQwMDcyNTR9.HRWvQhAc2zpsPpKFSOX4tMW85QW9U_rzf4jXo1xr_sI"

# Test protected route (with token)
   # First, get a token from login/register, then:
   TOKEN="your-jwt-token-here"
   
   curl http://localhost:3000/api/items \
     -H "Authorization: Bearer $TOKEN"