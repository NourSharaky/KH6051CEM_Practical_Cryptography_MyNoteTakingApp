
# MyNoteTakingApp

MyNoteTakingApp is a secure web-based notetaking application designed for users who prioritize data confidentiality and integrity. It provides a user-friendly platform for creating, storing, and sharing notes while ensuring a high level of security against potential threats in the digital environment. Whether you're a student, professional, or anyone seeking a secure notetaking solution, MyNoteTakingApp offers a blend of cutting-edge cryptographic practices and intuitive design.


## Features

- User-Friendly Interface: Offers an intuitive and aesthetically pleasing user interface designed for ease of use and efficient interaction.
- Responsive Design: Built with React for frontend responsiveness, enabling seamless user experiences across various devices and screen sizes.
- Secure Encryption: Utilizes advanced cryptographic algorithms, including SHA256 for password hashing and AES for symmetric encryption, ensuring the confidentiality of user data.
- JWT Authentication: Implements JSON Web Tokens (JWT) for secure user authentication, enhancing the overall security of the application.
- CSRF Protection: Guards against Cross-Site Request Forgery (CSRF) attacks by implementing anti-CSRF tokens, following industry best practices.
- HTTPS with RSA Encryption: Establishes secure communication channels using HTTPS with RSA encryption, ensuring the integrity and confidentiality of data during transmission.
- Dynamic Key Management: Implements a dynamic and secure key management system tailored to specific cryptographic components, such as CSRF protection, JWT authentication, AES encryption, and TLS key exchange.
- Data Confidentiality at Rest: Safeguards user information in the database through a combination of encryption, hashing, and encoding techniques, preventing unauthorized access and ensuring data remains unreadable.

## Tech Stack

 **Backend**
- Framework: Flask (a microframework for Python)
- Database ORM: SQLAlchemy (Object-Relational Mapping for Python)

**Frontend**
- HTML
- JavaScript
- CSS



## Run Locally

Clone the project

```bash
  git clone https://github.com/NourSharaky/KH6051CEM_Practical_Cryptography_MyNoteTakingApp.git
```

Go to the project directory

```bash
  cd KH6051CEM_Practical_Cryptography_MyNoteTakingApp
```

Activate Virtual Environment
```bash
  .\NoteTaking\scripts\activate
```

Install dependencies

```bash
  pip install -r requirements.txt --force
```

Go to NoteTaking folder

```bash
  cd NoteTaking
```

Run Server

```bash
  python app.py
```


## Documentation

[Documentation](https://elsewedyedu1-my.sharepoint.com/:b:/g/personal/ns00149_tkh_edu_eg/EaYpv6hPQF5LqpPHWMmvNJwBCAlPcL2KFrWWpXemTY09Wg?e=L7uxW3)


## Authors

- [@NourSharaky](https://github.com/NourSharaky)

