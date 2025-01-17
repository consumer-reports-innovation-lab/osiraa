from django.shortcuts import render
from django.http import HttpResponse


def index(request):
    context = {}
    return render(request, 'drp_aa_mvp/index.html', context)

