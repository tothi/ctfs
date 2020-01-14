#!/usr/bin/python
#

import base64
import re
import requests
import os

URL="https://fridosleigh.com/api/capteha/request"
IMGDIR="./traindata"
ROUNDS=200

i = 0
while i < ROUNDS:
    r = requests.post(URL)

    labels = r.json()['select_type'].split(',')
    labels = list(map(lambda s: re.sub(r'^ (and )?', '', s), labels))
    #print(labels)
    try:
        labels_old = open("%s/labels.txt" % IMGDIR, "r").readlines()
        labels_old = list(map(lambda s: s.strip(), labels_old))
    except:
        labels_old = []
    labels = list(set(labels + labels_old))
    with open("%s/labels.txt" % IMGDIR, "w") as f:
        for label in labels:
            f.write("%s\n" % label)
    print("{} labels, ".format(len(labels)), end=" ")

    for img in r.json()['images']:
        open("%s/%s.png" % (IMGDIR, img['uuid']), "wb").write(base64.b64decode(img['base64']))

    print("{} unique images to train".format(len([name for name in os.listdir(IMGDIR) if name.endswith(".png")])))

    i += 1
