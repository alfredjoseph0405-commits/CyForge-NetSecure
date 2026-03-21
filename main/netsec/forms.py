from django import forms


class keyfrm(forms.Form):
    ky=forms.CharField(label="Enter Key:  ")

class ipfrm(forms.Form):
    ipaddr=forms.CharField(max_length=15, label="Enter a private ip address:  ")
