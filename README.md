This project presents a Secure Microservice Web Application built with modern 
containerization and security practices. The application implements a distributed architecture 
using Docker containers, featuring separate microservices for user authentication and product 
management. The system employs JWT-based authentication, MongoDB for data persistence, 
and Nginx as a reverse proxy gateway.

 Key Features 
 Security Features 
• JWT Cookie Authentication: Secure, stateless authentication using HTTP-only cookies 
• Role-Based Access Control: Distinct permissions for admin and regular users 
• Password Security: PBKDF2-SHA256 hashing for password storage 
• Input Validation: MongoDB injection protection and form validation 
• CSRF Protection: Cross-site request forgery prevention using Flask-WTF 
Application Features 
• User Management: Registration, login, logout functionality 
• Product Management: Full CRUD operations for product catalog 
• Admin Dashboard: Comprehensive product management interface 
• Rate Limiting: API protection against abuse 
• Responsive UI: Bootstrap-based responsive design with dark theme 
Technical Features 
• Containerized Services: Docker-based microservice deployment 
• Database Integration: MongoDB with separate databases for each service 
• Reverse Proxy: Nginx gateway for request routing 
• Comprehensive Testing: Unit tests for core functionality

Routes: 
• / - Public product listing 
• /add - Add new product (admin only) 
• /manage - Product management dashboard (admin only) 
• /edit/<id> - Edit existing product (admin only) 
• /delete/<id> - Delete product (admin only) 
• /api/products - JSON API endpoint

 Nginx Gateway 
Configuration: 
• Routes /user/ requests to user-service:5000 
• Routes /product/ requests to product-service:5001 
• Handles proper header forwarding 
• Manages upstream server communication 
