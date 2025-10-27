highly_sensitive = [
    "UK_NINO",            # UK National Insurance Number
    "US_SSN",             # US Social Security Number
    "US_ITIN",            # US Individual Taxpayer Identification Number
    "US_DRIVER_LICENSE",
    "US_BANK_NUMBER",
    "CREDIT_CARD",
    "IBAN_CODE",
    "AADHAAR",            # Indian biometric ID
    "IN_AADHAAR",
    "IN_PAN",             # Indian Permanent Account Number
    "IN_PASSPORT",
    "IN_VOTER",
    "US_PASSPORT"
]
moderately_sensitive = [
    "MEDICAL_LICENSE",
    "CRYPTO",             # Crypto wallet or address (depends on usage)
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "IN_VEHICLE_REGISTRATION"
]
less_sensitive = [
    "PERSON",             # Names are generally considered less sensitive =
    "LOCATION" ,           # City-level or coarse-grained location
    "FIRST_NAME",
    "LAST_NAME"
]