from django import forms


class keyfrm(forms.Form):
    ky=forms.CharField(label="Enter Key:  ")
class BanditForm(forms.Form):
    file = forms.FileField(required=False)
    git = forms.URLField(required=False)
