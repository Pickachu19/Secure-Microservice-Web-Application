# Secure Microservice Web Application

This project presents a **Secure Microservice Web Application** built with modern containerization and security practices. The application follows a distributed architecture using Docker containers, featuring separate microservices for **user authentication** and **product management**.

---

## 🔐 Key Security Features

- **JWT Cookie Authentication**: Secure, stateless authentication using HTTP-only cookies  
- **Role-Based Access Control**: Distinct permissions for admin and regular users  
- **Password Security**: PBKDF2-SHA256 hashing for password storage  
- **Input Validation**: MongoDB injection protection and form validation  
- **CSRF Protection**: Flask-WTF-based CSRF prevention  

---

## ⚙️ Application Features

- **User Management**: Registration, login, and logout functionality  
- **Product Management**: Full CRUD operations for product catalog  
- **Admin Dashboard**: Admin-only interface for managing products  
- **Rate Limiting**: API protection against abuse  
- **Responsive UI**: Bootstrap-based responsive design with dark theme  

---

## 🧪 Technical Features

- **Containerized Services**: Docker-based microservice deployment  
- **Database Integration**: MongoDB with separate databases per service  
- **Reverse Proxy**: Nginx gateway for request routing  
- **Comprehensive Testing**: Unit tests for core functionality  

---

## 🚀 Application Routes

| Route               | Description                               | Access        |
|--------------------|-------------------------------------------|---------------|
| `/`                | Public product listing                    | Public        |
| `/add`             | Add new product                           | Admin only    |
| `/manage`          | Product management dashboard              | Admin only    |
| `/edit/<id>`       | Edit existing product                     | Admin only    |
| `/delete/<id>`     | Delete product                            | Admin only    |
| `/api/products`    | JSON API endpoint for products            | Public/API    |

---

## 🌐 Nginx Gateway Configuration

- Routes `/user/` requests to `user-service:5000`
- Routes `/product/` requests to `product-service:5001`
- Handles proper header forwarding
- Manages upstream server communication

---

## 📦 Technologies Used

- **Frontend**: HTML, Bootstrap, Flask templates  
- **Backend**: Python (Flask), MongoDB  
- **Containerization**: Docker  
- **Gateway**: Nginx  
- **Authentication**: JWT (via secure cookies)

---



