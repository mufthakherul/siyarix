from siyarix.credential_store import CredentialStore
import os

store = CredentialStore(master_password=TestPassword123!)
store.store(gemini, AIzaSyBoDkJmkfQ4TtCIGlDvPK0K7fPlIsEdE_Y, api_key)
print(Successfully initialized credential store!)
