# TokenAuthGen API

An ASP.NET Core Web API that provides secure user authentication, email verification, and custom access token generation and validation.

## Features

- **User Signup**: New users can register with their email.
- **Email Verification**: Sends a confirmation email via MailKit to verify user identity.
- **User Login**: Authenticates users using JWT and returns access tokens.
- **Token Generator**: Creates custom 6-character access tokens.
- **Token Validator**: Checks if an access token is valid, expired, or invalid.

## Technologies Used

- ASP.NET Core
- Entity Framework Core
- SQL Server
- MailKit (for email sending)
- JWT (JSON Web Tokens)

## Setup Instructions

1. **Clone the repository**
   ```bash
   git clone https://github.com/Smartvik2/TokenAuthGen.git
