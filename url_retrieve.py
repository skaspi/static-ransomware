#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Created on Mon Jan 1 21:51:16 2018

@authors Rafael,Dmitriy
Ransomware Detection Project
Technion, Haifa, Israel

Python script for downloading files from the attached URLs in an e-mail.
We used json package to get values that correspond to the following JSON keys:
              *** [value][bodyPreview]
              *** [value][body][0][content]

We extracted the URL themselves with regex and BeautifulSoup's parser.
We downloaded the files with dedicated urllib package.

All the credits for the is_downloadable() and get_filename_from_cd() functions goes to Avi Aryan :))

Avi Aryan's post --> https://www.codementor.io/aviaryan/downloading-files-from-urls-in-python-77q3bs0un
"""

import re
import json
import shutil
import requests
from bs4 import BeautifulSoup
from urllib.request import urlopen


def get_filename_from_cd(cd):
    """
    Get filename from content-disposition
    """
    if not cd:
        return None
    fname = re.findall('filename=(.+)', cd)
    if len(fname) == 0:
        return None
    return fname[0]


def is_downloadable(url):
    """
    Does the url contain a downloadable resource
    """
    h = requests.head(url, allow_redirects=True)
    header = h.headers
    content_type = header.get('content-type')
    if 'text' in content_type.lower():
        return False
    if 'html' in content_type.lower():
        return False
    return True


def main():
    with open('data.json') as data_file:
        data = json.load(data_file)

    text = data["value"][0]["bodyPreview"]

    body_links = (re.findall("(?P<url>https?://[^\s]+)", text))

    page = data["value"][0]["body"]["content"]

    soup = BeautifulSoup(page, "html.parser")

    data_file.close()

    links = []

    for link in soup.find_all('a'):
        if link.get('href') not in links:
            links.append(link.get('href'))

    merged = list(set(links + body_links))

    for url in merged:
        try:
            request = requests.get(url)
            if request.status_code // 100 < 4:
                if is_downloadable(url):
                    cd = request.headers.get('content-disposition')
                    if cd:
                        filename = get_filename_from_cd(cd)
                    else:
                        filename = url.rsplit('/', 1)[1]
                    with urlopen(url) as response, open(filename, 'wb') as out_file:
                        shutil.copyfileobj(response, out_file)

        except requests.exceptions.MissingSchema:
            pass

        except requests.URLRequired:
            pass

        except requests.ConnectionError:
            pass


if __name__ == '__main__':
    main()
