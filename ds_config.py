# ds_config.py
#
# DocuSign configuration settings
import os

DS_CONFIG = {
    "ds_client_id": "c0c6ac35-fa68-4a3d-9260-16b28d8f7a5e", # The app's DocuSign integration key
    "ds_client_secret": "4c482ff9-bfd1-4026-b4bd-0d0cb2e8d8a6", # The app's DocuSign integration key's secret
    "signer_email": "",
    "signer_name": "",
    "app_url": "https://veridocglobaldocusignpython.azurewebsites.net/", # The url of the application. Eg http://localhost:5000
    # NOTE: You must add a Redirect URI of appUrl/ds/callback to your Integration Key.
    #       Example: http:#localhost:5000/ds/callback
    "authorization_server": "https://account-d.docusign.com",
    "session_secret": "hhjgdijhihbdscjmkdl", # Secret for encrypting session cookie content
                                          # Use any random string of characters
    "allow_silent_authentication": True, # a user can be silently authenticated if they have an
    # active login session on another tab of the same browser
    "target_account_id": None, # Set if you want a specific DocuSign AccountId, 
                               # If None, the user's default account will be used.
    #"demo_doc_path": "demo_documents",
    #"doc_salary_docx": "World_Wide_Corp_salary.docx",
    #"doc_docx": "World_Wide_Corp_Battle_Plan_Trafalgar.docx",
    #"doc_pdf":  "World_Wide_Corp_lorem.pdf",
    # Payment gateway information is optional
    "gateway_account_id": "{DS_PAYMENT_GATEWAY_ID}",
    "gateway_name": "stripe",
    "gateway_display_name": "Stripe",
    "github_example_url": "https://github.com/docusign/eg-03-python-auth-code-grant/tree/master/app/",
    "documentation": "" # Use an empty string to indicate no documentation path.
}
