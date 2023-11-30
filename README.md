# QR Code-Based Mobile Payment System for Android

## Overview
This Android application implements [a QR code-based mobile payment system](https://ieeexplore.ieee.org/document/7311922). Leveraging the BouncyCastle library for enhanced security, the app supports user registration, balance management, and QR code-enabled payment functionalities.

## Features
- **User Registration**: Registration process for new users via a remote service.
- **Balance Management**: Users can load and withdraw funds from their account within the app.
- **Customer Transactions**: Customers can scan QR codes to select products and execute payments.
- **Merchant Transactions**: Merchants have the capability to scan QR codes to accept orders and generate order.

## Prerequisites
- Android Studio
- Minimum SDK version: 28
- BouncyCastle library

## Installation
1. Clone the repository:
2. Open the project in Android Studio:
3. Replace server IP with your own, and use your own keypair.
## Building the Application
Build the app using Android Studio:
1. Navigate to `Build` -> `Make Project` to build the app.
2. To run the app, select `Run` -> `Run 'app'`.

## Acknowledgements
A heartfelt thanks to the BouncyCastle library for their comprehensive cryptographic solutions, enhancing the security features of this mobile payment system.
