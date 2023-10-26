# forms.py

from django import forms

class AWSConfigForm(forms.Form):
    access_key = forms.CharField(label='AWS Access Key', max_length=100)
    secret_key = forms.CharField(label='AWS Secret Key', max_length=100)
class EmailForm(forms.Form):
    recipient_email = forms.EmailField(label="Recipient's Email")